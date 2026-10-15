// SPDX-License-Identifier: GPL-2.0
/*
 * Minimal /dev/qseecom shim for mainline, backed by the qcom_scm QSEECOM
 * interface. Enough of the downstream QSEECom ABI for the Goodix fingerprint
 * userspace stack (libQSEEComAPI -> libgf_ca -> fingerprint.goodix.so):
 *   LOAD_APP, SET_MEM_PARAM, SEND_CMD, SEND_MODFD_CMD, UNLOAD_APP,
 *   GET_QSEOS_VERSION, SET_BUS_SCALING, and listener RECEIVE/SEND_RESP stubs.
 *
 * userspace mmaps the device to get a shared buffer and builds commands there;
 * because gfber requires TZ-registered (tzmem-pool) buffers, every SMC bounces
 * through a per-handle tzmem buffer (copy in, SCM, copy out).
 */
#include <linux/dma-buf.h>
#include <linux/iosys-map.h>
#include <linux/dma-mapping.h>
#include <linux/elf.h>
#include <linux/firmware.h>
#include <linux/firmware/qcom/qcom_scm.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#define QSEECOM_IOC_MAGIC	0x97
#define MAX_APP_NAME_SIZE	64
#define MAX_ION_FD		4

struct qseecom_send_cmd_req {
	void *cmd_req_buf;
	unsigned int cmd_req_len;
	void *resp_buf;
	unsigned int resp_len;
};
struct qseecom_ion_fd_info {
	s32 fd;
	u32 cmd_buf_offset;
};
struct qseecom_send_modfd_cmd_req {
	void *cmd_req_buf;
	unsigned int cmd_req_len;
	void *resp_buf;
	unsigned int resp_len;
	struct qseecom_ion_fd_info ifd_data[MAX_ION_FD];
};
struct qseecom_load_img_req {
	u32 mdt_len;
	u32 img_len;
	s32 ifd_data_fd;
	char img_name[MAX_APP_NAME_SIZE];
	u32 app_arch;
	u32 app_id;
};
struct qseecom_set_sb_mem_param_req {
	s32 ifd_data_fd;
	void *virt_sb_base;
	u32 sb_len;
};
struct qseecom_qseos_version_req {
	unsigned int qseos_version;
};

#define QSEECOM_IOCTL_SEND_CMD_REQ \
	_IOWR(QSEECOM_IOC_MAGIC, 3, struct qseecom_send_cmd_req)
#define QSEECOM_IOCTL_SEND_MODFD_CMD_REQ \
	_IOWR(QSEECOM_IOC_MAGIC, 4, struct qseecom_send_modfd_cmd_req)
#define QSEECOM_IOCTL_RECEIVE_REQ	_IO(QSEECOM_IOC_MAGIC, 5)
#define QSEECOM_IOCTL_SEND_RESP_REQ	_IO(QSEECOM_IOC_MAGIC, 6)
#define QSEECOM_IOCTL_LOAD_APP_REQ \
	_IOWR(QSEECOM_IOC_MAGIC, 7, struct qseecom_load_img_req)
#define QSEECOM_IOCTL_SET_MEM_PARAM_REQ \
	_IOWR(QSEECOM_IOC_MAGIC, 8, struct qseecom_set_sb_mem_param_req)
#define QSEECOM_IOCTL_UNLOAD_APP_REQ	_IO(QSEECOM_IOC_MAGIC, 9)
#define QSEECOM_IOCTL_GET_QSEOS_VERSION_REQ \
	_IOWR(QSEECOM_IOC_MAGIC, 10, struct qseecom_qseos_version_req)
#define QSEECOM_IOCTL_PERF_ENABLE_REQ	_IO(QSEECOM_IOC_MAGIC, 11)
#define QSEECOM_IOCTL_PERF_DISABLE_REQ	_IO(QSEECOM_IOC_MAGIC, 12)
#define QSEECOM_IOCTL_SET_BUS_SCALING_REQ _IOWR(QSEECOM_IOC_MAGIC, 23, int)

/* SCM owner/svc/cmd for app send (TZ_APPS) */
#define TZ_APPS			48

struct qseecom_handle {
	void *sb_kvirt;			/* coherent shared buffer (mmap'd to user) */
	dma_addr_t sb_dma;
	size_t sb_len;
	unsigned long user_sb_base;	/* userspace VA from SET_MEM_PARAM */
	void *tz;			/* tzmem bounce buffer (shared buf) */
	phys_addr_t tz_phys;
	void *aux;			/* tzmem for modfd payloads */
	phys_addr_t aux_phys;
	u32 app_id;
	bool sb_registered;
	struct mutex lock;
};

static struct miscdevice qseecom_misc;
static struct device *h_misc_dev(void) { return qseecom_misc.this_device; }
static bool cmnlib_loaded;

static int qs_load_ta(struct qseecom_handle *h, const char *name, u32 *app_id)
{
	/* reuse split-image loading: qsee/<name>.mdt + .bNN via request_firmware */
	const struct firmware *mdt = NULL, *seg = NULL;
	struct qcom_scm_qseecom_raw_resp r = {};
	char fn[80];
	void *img = NULL;
	dma_addr_t img_dma;
	size_t total, off;
	unsigned int phnum = 0, i;
	int ret;
	u8 cls;

	/* already loaded? gfber registers its name, so a lookup returns its id */
	{
		u32 existing = 0;

		if (qcom_scm_qseecom_app_get_id(name, &existing) == 0 && existing) {
			*app_id = existing;
			return 0;
		}
	}

	snprintf(fn, sizeof(fn), "qsee/%s.mdt", name);
	ret = request_firmware(&mdt, fn, h_misc_dev());
	if (ret)
		return ret;
	cls = mdt->data[EI_CLASS];
	if (cls == ELFCLASS32)
		phnum = ((const struct elf32_hdr *)mdt->data)->e_phnum;
	else if (cls == ELFCLASS64)
		phnum = ((const struct elf64_hdr *)mdt->data)->e_phnum;
	if (!phnum || phnum > 64) {
		release_firmware(mdt);
		return -EINVAL;
	}
	total = mdt->size;
	for (i = 0; i < phnum; i++) {
		snprintf(fn, sizeof(fn), "qsee/%s.b%02u", name, i);
		ret = request_firmware(&seg, fn, h_misc_dev());
		if (ret) {
			release_firmware(mdt);
			return ret;
		}
		total += seg->size;
		release_firmware(seg);
		seg = NULL;
	}
	img = qcom_scm_qseecom_alloc_image(total, &img_dma);
	if (!img) {
		release_firmware(mdt);
		return -ENOMEM;
	}
	memcpy(img, mdt->data, mdt->size);
	off = mdt->size;
	for (i = 0; i < phnum; i++) {
		snprintf(fn, sizeof(fn), "qsee/%s.b%02u", name, i);
		if (request_firmware(&seg, fn, h_misc_dev()) == 0) {
			memcpy(img + off, seg->data, seg->size);
			off += seg->size;
			release_firmware(seg);
			seg = NULL;
		}
	}
	/* app region notify (harmless if already set) */
	qcom_scm_qseecom_app_region_notify(0x86d00000, 0x2200000, &r);

	/* common library must be loaded before any ELF32 TA */
	if (!cmnlib_loaded && cls == ELFCLASS32) {
		const struct firmware *lmdt = NULL, *lseg = NULL;
		void *limg; dma_addr_t ldma; size_t ltot, loff; unsigned int lph, j;

		if (request_firmware(&lmdt, "qsee/cmnlib.mdt", h_misc_dev()) == 0) {
			lph = ((const struct elf32_hdr *)lmdt->data)->e_phnum;
			ltot = lmdt->size;
			for (j = 0; j < lph; j++) {
				snprintf(fn, sizeof(fn), "qsee/cmnlib.b%02u", j);
				if (request_firmware(&lseg, fn, h_misc_dev()) == 0) {
					ltot += lseg->size; release_firmware(lseg); lseg = NULL;
				}
			}
			limg = qcom_scm_qseecom_alloc_image(ltot, &ldma);
			if (limg) {
				memcpy(limg, lmdt->data, lmdt->size); loff = lmdt->size;
				for (j = 0; j < lph; j++) {
					snprintf(fn, sizeof(fn), "qsee/cmnlib.b%02u", j);
					if (request_firmware(&lseg, fn, h_misc_dev()) == 0) {
						memcpy(limg + loff, lseg->data, lseg->size);
						loff += lseg->size; release_firmware(lseg); lseg = NULL;
					}
				}
				if (qcom_scm_qseecom_load_image(true, lmdt->size, ltot, ldma, &r) == 0 && !r.result)
					cmnlib_loaded = true;
				qcom_scm_qseecom_free_image(ltot, limg, ldma);
			}
			release_firmware(lmdt);
		}
	}

	/* APP_START (retry once; first attempt after a cmnlib load can fail) */
	ret = qcom_scm_qseecom_load_image(false, mdt->size, total, img_dma, &r);
	if (ret || r.result)
		ret = qcom_scm_qseecom_load_image(false, mdt->size, total, img_dma, &r);
	release_firmware(mdt);
	qcom_scm_qseecom_free_image(total, img, img_dma);
	if (ret)
		return ret;
	if ((s64)r.result == -38) {	/* QSEOS_RESULT_FAIL_APP_ALREADY_LOADED */
		u32 existing = 0;

		if (qcom_scm_qseecom_app_get_id(name, &existing) == 0 && existing) {
			*app_id = existing;
			return 0;
		}
		return -EEXIST;
	}
	if (r.result)
		return -EIO;
	*app_id = r.data;
	return 0;
}

static int qs_send(struct qseecom_handle *h, u32 req_off, u32 req_len,
		   u32 rsp_off, u32 rsp_len, phys_addr_t sgl, size_t sgl_len)
{
	struct qcom_scm_qseecom_raw_resp r = {};
	int ret;

	/* bounce the whole shared buffer into tzmem */
	memcpy(h->tz, h->sb_kvirt, h->sb_len);
	ret = qcom_scm_qseecom_app_send_phys(h->app_id,
			h->tz_phys + req_off, req_len,
			h->tz_phys + rsp_off, rsp_len, sgl, sgl_len, &r);
	/* copy results back */
	memcpy(h->sb_kvirt, h->tz, h->sb_len);
	if (ret)
		return ret;
	return r.result ? -EIO : 0;
}

static long qs_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	struct qseecom_handle *h = f->private_data;
	void __user *uarg = (void __user *)arg;
	int ret = 0;

	mutex_lock(&h->lock);
	switch (cmd) {
	case QSEECOM_IOCTL_GET_QSEOS_VERSION_REQ: {
		struct qseecom_qseos_version_req v = { .qseos_version = 0x1400000 };

		if (copy_to_user(uarg, &v, sizeof(v)))
			ret = -EFAULT;
		break;
	}
	case QSEECOM_IOCTL_SET_MEM_PARAM_REQ: {
		struct qseecom_set_sb_mem_param_req p;

		if (copy_from_user(&p, uarg, sizeof(p))) { ret = -EFAULT; break; }
		h->user_sb_base = (unsigned long)p.virt_sb_base;
		h->sb_registered = true;
		break;
	}
	case QSEECOM_IOCTL_LOAD_APP_REQ: {
		struct qseecom_load_img_req req;

		if (copy_from_user(&req, uarg, sizeof(req))) { ret = -EFAULT; break; }
		req.img_name[MAX_APP_NAME_SIZE - 1] = 0;
		ret = qs_load_ta(h, req.img_name, &req.app_id);
		if (!ret) {
			h->app_id = req.app_id;
			if (copy_to_user(uarg, &req, sizeof(req)))
				ret = -EFAULT;
		}
		break;
	}
	case QSEECOM_IOCTL_UNLOAD_APP_REQ: {
		/* Force-unload the TA from TZ so it can be reloaded fresh (clears a
		 * wedged gfber session without a reboot). */
		struct qcom_scm_qseecom_raw_resp r = {};

		if (h->app_id) {
			ret = qcom_scm_qseecom_app_shutdown(h->app_id, &r);
			pr_info("qseecom: shutdown app_id=%u -> ret=%d result=%lld\n",
				h->app_id, ret, r.result);
		}
		h->app_id = 0;
		break;
	}
	case QSEECOM_IOCTL_SEND_CMD_REQ: {
		struct qseecom_send_cmd_req req;
		u32 req_off, rsp_off;

		if (copy_from_user(&req, uarg, sizeof(req))) { ret = -EFAULT; break; }
		req_off = (unsigned long)req.cmd_req_buf - h->user_sb_base;
		rsp_off = (unsigned long)req.resp_buf - h->user_sb_base;
		if (req_off + req.cmd_req_len > h->sb_len ||
		    rsp_off + req.resp_len > h->sb_len) { ret = -EINVAL; break; }
		ret = qs_send(h, req_off, req.cmd_req_len, rsp_off, req.resp_len, 0, 0);
		break;
	}
	case QSEECOM_IOCTL_SEND_MODFD_CMD_REQ: {
		struct qseecom_send_modfd_cmd_req req;
		struct qcom_scm_qseecom_raw_resp r = {};
		struct dma_buf *db[MAX_ION_FD] = { NULL };
		struct iosys_map map[MAX_ION_FD] = {};
		size_t plen[MAX_ION_FD] = { 0 };
		u32 poff[MAX_ION_FD] = { 0 };
		u32 req_off, rsp_off, cur = 0;
		int i;

		if (copy_from_user(&req, uarg, sizeof(req))) { ret = -EFAULT; break; }
		req_off = (unsigned long)req.cmd_req_buf - h->user_sb_base;
		rsp_off = (unsigned long)req.resp_buf - h->user_sb_base;
		if (req_off + req.cmd_req_len > h->sb_len ||
		    rsp_off + req.resp_len > h->sb_len) { ret = -EINVAL; break; }

		dev_info(h_misc_dev(), "modfd: req_off=%u len=%u ifd0.fd=%d off=%u\n",
			 req_off, req.cmd_req_len, req.ifd_data[0].fd,
			 req.ifd_data[0].cmd_buf_offset);
		/* bounce the shared buffer into tzmem */
		memcpy(h->tz, h->sb_kvirt, h->sb_len);

		/* resolve each fd: copy its dma-buf into aux tzmem, patch phys */
		for (i = 0; i < MAX_ION_FD; i++) {
			struct dma_buf *d;
			u32 off = req.ifd_data[i].cmd_buf_offset;

			if (req.ifd_data[i].fd <= 0)
				continue;
			d = dma_buf_get(req.ifd_data[i].fd);
			if (IS_ERR(d)) {
				dev_warn(h_misc_dev(), "modfd: dma_buf_get(fd=%d)=%ld\n",
					 req.ifd_data[i].fd, PTR_ERR(d));
				ret = PTR_ERR(d); db[i] = NULL; goto modfd_unwind;
			}
			db[i] = d;
			plen[i] = d->size;
			cur = ALIGN(cur, 4096);
			if (cur + plen[i] > h->sb_len) { ret = -ENOMEM; goto modfd_unwind; }
			poff[i] = cur;
			cur += plen[i];
			if (dma_buf_begin_cpu_access(d, DMA_BIDIRECTIONAL)) { ret = -EIO; goto modfd_unwind; }
			if (dma_buf_vmap(d, &map[i])) { dma_buf_end_cpu_access(d, DMA_BIDIRECTIONAL); ret = -ENOMEM; goto modfd_unwind; }
			memcpy((u8 *)h->aux + poff[i], map[i].vaddr, plen[i]);
			/* patch the tzmem payload phys into the cmd buffer */
			if (req_off + off + 4 <= h->sb_len)
				*(u32 *)((u8 *)h->tz + req_off + off) =
					lower_32_bits(h->aux_phys + poff[i]);
		}

		ret = qcom_scm_qseecom_app_send_phys(h->app_id,
				h->tz_phys + req_off, req.cmd_req_len,
				h->tz_phys + rsp_off, req.resp_len, 0, 0, &r);
		if (!ret && r.result)
			ret = -EIO;

		/* copy payloads back to their dma-bufs (TA output), then release */
modfd_unwind:
		for (i = 0; i < MAX_ION_FD; i++) {
			if (!db[i])
				continue;
			if (map[i].vaddr) {
				if (!ret)
					memcpy(map[i].vaddr, (u8 *)h->aux + poff[i], plen[i]);
				dma_buf_vunmap(db[i], &map[i]);
				dma_buf_end_cpu_access(db[i], DMA_BIDIRECTIONAL);
			}
			dma_buf_put(db[i]);
		}
		/* copy the shared buffer back out (response) */
		memcpy(h->sb_kvirt, h->tz, h->sb_len);
		break;
	}
	case QSEECOM_IOCTL_RECEIVE_REQ:
	case QSEECOM_IOCTL_SEND_RESP_REQ:
		/* no listeners registered in this shim yet */
		ret = 0;
		break;
	case QSEECOM_IOCTL_SET_BUS_SCALING_REQ:
	case QSEECOM_IOCTL_PERF_ENABLE_REQ:
	case QSEECOM_IOCTL_PERF_DISABLE_REQ:
		ret = 0;
		break;
	default:
		ret = -ENOTTY;
	}
	mutex_unlock(&h->lock);
	return ret;
}

static int qs_mmap(struct file *f, struct vm_area_struct *vma)
{
	struct qseecom_handle *h = f->private_data;
	size_t len = vma->vm_end - vma->vm_start;

	if (h->sb_kvirt)		/* one sb per handle */
		return -EBUSY;
	if (len > SZ_1M)
		return -EINVAL;
	h->sb_kvirt = vmalloc_user(len);
	if (!h->sb_kvirt)
		return -ENOMEM;
	h->tz = qcom_scm_qseecom_tzmem_alloc(len, &h->tz_phys);
	h->aux = qcom_scm_qseecom_tzmem_alloc(len, &h->aux_phys);
	if (!h->tz || !h->aux) {
		if (h->tz) qcom_scm_qseecom_tzmem_free(h->tz);
		if (h->aux) qcom_scm_qseecom_tzmem_free(h->aux);
		h->tz = h->aux = NULL;
		vfree(h->sb_kvirt);
		h->sb_kvirt = NULL;
		return -ENOMEM;
	}
	h->sb_len = len;
	return remap_vmalloc_range(vma, h->sb_kvirt, 0);
}

static int qs_open(struct inode *ino, struct file *f)
{
	struct qseecom_handle *h = kzalloc(sizeof(*h), GFP_KERNEL);

	if (!h)
		return -ENOMEM;
	mutex_init(&h->lock);
	f->private_data = h;
	return 0;
}

static int qs_release(struct inode *ino, struct file *f)
{
	struct qseecom_handle *h = f->private_data;

	if (h->tz)
		qcom_scm_qseecom_tzmem_free(h->tz);
	if (h->aux)
		qcom_scm_qseecom_tzmem_free(h->aux);
	if (h->sb_kvirt)
		vfree(h->sb_kvirt);
	kfree(h);
	return 0;
}

static const struct file_operations qs_fops = {
	.owner = THIS_MODULE,
	.open = qs_open,
	.release = qs_release,
	.unlocked_ioctl = qs_ioctl,
	.compat_ioctl = qs_ioctl,
	.mmap = qs_mmap,
};

static struct miscdevice qseecom_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "qseecom",
	.fops = &qs_fops,
};

static int __init qs_init(void)
{
	return misc_register(&qseecom_misc);
}

static void __exit qs_exit(void)
{
	misc_deregister(&qseecom_misc);
}

module_init(qs_init);
module_exit(qs_exit);
MODULE_DESCRIPTION("Minimal /dev/qseecom shim over qcom_scm (fingerprint)");
MODULE_IMPORT_NS("DMA_BUF");
MODULE_LICENSE("GPL");
