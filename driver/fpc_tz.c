// SPDX-License-Identifier: GPL-2.0
/*
 * Test-only: drive the HLOS side of the FPC fingerprint sensor (vdd, reset,
 * irq) and talk to the FPC trusted application in QSEE.
 *
 * Transport (from the FPC HAL): a 64-byte QSEECom request {length, addr}
 * where addr is the physical address of a page-aligned data buffer whose
 * first words are {group_id, cmd_id, ret_val, ...}; the 64-byte response
 * holds an int32 status.
 */
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/firmware/qcom/qcom_scm.h>
#include <linux/gpio/consumer.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/clk.h>
#include <linux/regulator/consumer.h>
#include <linux/slab.h>
#include <linux/sysfs.h>

static uint app_id;
module_param(app_id, uint, 0644);
MODULE_PARM_DESC(app_id, "QSEE app id of the loaded FPC TA (0 = look up app_name)");
static char *app_name = "fpcber";
module_param(app_name, charp, 0444);
static bool power = true;
module_param(power, bool, 0444);
MODULE_PARM_DESC(power, "enable vdd and pulse reset at probe");
static bool talk = true;
module_param(talk, bool, 0444);
static char *seq = "9:2,10:0,6:3,10:4";
module_param(seq, charp, 0444);
MODULE_PARM_DESC(seq, "comma list of group:cmd to send at probe");
static bool whitelist;
module_param(whitelist, bool, 0644);
MODULE_PARM_DESC(whitelist, "use SEND_DATA_WITH_WHITELIST (sglist) variant");

static bool km_init = true;
module_param(km_init, bool, 0444);
MODULE_PARM_DESC(km_init, "run keymaster64 key-data handshake + SET_KEY_DATA at probe");
static uint km_app_id = 1;
module_param(km_app_id, uint, 0644);
MODULE_PARM_DESC(km_app_id, "keymaster64 QSEE app id (bootloader-loaded, usually 1)");
static uint spi_rate;
module_param(spi_rate, uint, 0444);
MODULE_PARM_DESC(spi_rate, "if non-zero, clk_set_rate on the SPI SE clock before enable");

static uint gf_app_id;
module_param(gf_app_id, uint, 0644);
MODULE_PARM_DESC(gf_app_id, "Goodix TA (gfber) QSEE app id for gcmd (0 = disabled)");
static bool gf_whitelist;
module_param(gf_whitelist, bool, 0644);
MODULE_PARM_DESC(gf_whitelist, "use whitelist/sglist for the Goodix payload pointer");
static bool gf_key = true;
module_param(gf_key, bool, 0444);
MODULE_PARM_DESC(gf_key, "run Goodix keymaster key-set (cmd 109) at probe");

#define MSG_SIZE	8192
#define REQ_OFF		0
#define RSP_OFF		256
#define SGL_OFF		512
#define KM_RSP_OFF	4096
#define KM_RSP_LEN	1024
#define DATA_SIZE	4096

struct fpc_mod_cmd {
	u32 length;
	u32 addr;
};

struct sglist_info {
	u32 index_flags;
	u32 size_or_count;
};

struct fpc_tz {
	struct device *dev;
	struct regulator *vdd;
	struct gpio_desc *reset;
	struct gpio_desc *irq_gpio;
	struct clk *se_clk;
	void *gf_mem;
	phys_addr_t gf_mem_phys;
	int irq;
	atomic_t irq_count;
	void *msg;
	dma_addr_t msg_dma;
	void *data;
	dma_addr_t data_dma;
	struct mutex lock;
	bool powered;
};

static irqreturn_t fpc_tz_irq(int irq, void *p)
{
	struct fpc_tz *f = p;

	atomic_inc(&f->irq_count);
	dev_info(f->dev, "IRQ #%d (line now %d)\n", atomic_read(&f->irq_count),
		 gpiod_get_value_cansleep(f->irq_gpio));
	return IRQ_HANDLED;
}

static void fpc_tz_hw_reset(struct fpc_tz *f)
{
	gpiod_set_value_cansleep(f->reset, 0);	/* deasserted: line high */
	usleep_range(100, 200);
	gpiod_set_value_cansleep(f->reset, 1);	/* asserted: line low */
	usleep_range(5000, 5100);
	gpiod_set_value_cansleep(f->reset, 0);
	usleep_range(5000, 5100);
	dev_info(f->dev, "hw reset done, irq line %d\n",
		 gpiod_get_value_cansleep(f->irq_gpio));
}

static int fpc_tz_send(struct fpc_tz *f, u32 group, u32 cmd, u32 arg)
{
	struct fpc_mod_cmd *req = f->msg + REQ_OFF;
	s32 *rsp = f->msg + RSP_OFF;
	struct sglist_info *sgl = f->msg + SGL_OFF;
	struct qcom_scm_qseecom_raw_resp r = {};
	u32 *d = f->data;
	int ret;

	if (!app_id)
		return -ENODEV;

	mutex_lock(&f->lock);
	memset(f->data, 0, DATA_SIZE);
	d[0] = group;
	d[1] = cmd;
	d[2] = 0;
	d[3] = arg;
	memset(f->msg, 0, MSG_SIZE);
	req->length = DATA_SIZE;
	req->addr = lower_32_bits(f->data_dma);
	sgl[0].index_flags = BIT(31) | offsetof(struct fpc_mod_cmd, addr);
	sgl[0].size_or_count = DATA_SIZE;

	ret = qcom_scm_qseecom_app_send_phys(app_id,
			f->msg_dma + REQ_OFF, 64, f->msg_dma + RSP_OFF, 64,
			whitelist ? f->msg_dma + SGL_OFF : 0,
			whitelist ? 4 * sizeof(*sgl) : 0, &r);
	dev_info(f->dev,
		 "cmd %u:%u arg %u -> scm=%d result=%lld type=%#llx data=%#llx rsp=%d data=%08x %08x %08x %08x %08x %08x %08x %08x irqs=%d\n",
		 group, cmd, arg, ret, r.result, r.resp_type, r.data, *rsp,
		 d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7],
		 atomic_read(&f->irq_count));
	mutex_unlock(&f->lock);
	if (ret)
		return ret;
	return r.result ? -EIO : 0;
}

/*
 * Buffer command: the TA reads a data buffer laid out as
 * {u32 group_id, u32 cmd_id, s32 status, u32 length, <length bytes>}.
 * Header is 16 bytes (32-bit TA pointer layout), payload follows.
 */
static int fpc_tz_send_buf(struct fpc_tz *f, u32 group, u32 cmd,
			   const void *payload, u32 len)
{
	struct fpc_mod_cmd *req = f->msg + REQ_OFF;
	s32 *rsp = f->msg + RSP_OFF;
	struct sglist_info *sgl = f->msg + SGL_OFF;
	struct qcom_scm_qseecom_raw_resp r = {};
	u32 *d = f->data;
	int ret;

	if (!app_id)
		return -ENODEV;
	if (16 + len > DATA_SIZE)
		return -EMSGSIZE;

	mutex_lock(&f->lock);
	memset(f->data, 0, DATA_SIZE);
	d[0] = group;
	d[1] = cmd;
	d[2] = 0;
	d[3] = len;
	if (payload && len)
		memcpy((u8 *)f->data + 16, payload, len);

	memset(f->msg, 0, SGL_OFF + 64);
	req->length = (16 + len + 4095) & ~4095U;
	req->addr = lower_32_bits(f->data_dma);
	sgl[0].index_flags = BIT(31) | offsetof(struct fpc_mod_cmd, addr);
	sgl[0].size_or_count = req->length;

	ret = qcom_scm_qseecom_app_send_phys(app_id,
			f->msg_dma + REQ_OFF, 64, f->msg_dma + RSP_OFF, 64,
			whitelist ? f->msg_dma + SGL_OFF : 0,
			whitelist ? 4 * sizeof(*sgl) : 0, &r);
	dev_info(f->dev,
		 "buf %u:%u len %u -> scm=%d result=%lld rsp=%d hdr=%08x %08x %08x %08x\n",
		 group, cmd, len, ret, r.result, *rsp, d[0], d[1], d[2], d[3]);
	mutex_unlock(&f->lock);
	if (ret)
		return ret;
	return r.result ? -EIO : (s32)d[2];
}

/*
 * keymaster64 handshake (Sony fpc_init): plain SEND_DATA with a 64-byte
 * request {cmd_id=0x205, ret_val=0x02, length=0} and a 1024-byte response
 * {s32 status, u32 offset, u32 length, ...}; the key blob sits at rsp+offset.
 * Hand the blob to the FPC TA via SET_KEY_DATA (group 3 FPCDATA, cmd 5).
 */
static int fpc_tz_keymaster_init(struct fpc_tz *f)
{
	u32 *kreq = f->msg + REQ_OFF;
	u32 *krsp = f->msg + KM_RSP_OFF;
	struct qcom_scm_qseecom_raw_resp r = {};
	u32 off, len;
	void *blob;
	int ret;

	if (!km_app_id) {
		ret = qcom_scm_qseecom_app_get_id("keymaster64", &km_app_id);
		dev_info(f->dev, "keymaster64 lookup ret=%d id=%u\n", ret, km_app_id);
		if (ret || !km_app_id) {
			qcom_scm_qseecom_app_get_id("keymaster", &km_app_id);
			dev_info(f->dev, "keymaster lookup id=%u\n", km_app_id);
		}
		if (!km_app_id)
			return -ENODEV;
	}

	mutex_lock(&f->lock);
	memset(f->msg, 0, MSG_SIZE);
	kreq[0] = 0x205;	/* cmd_id */
	kreq[1] = 0x02;		/* ret_val */
	kreq[2] = 0;		/* length */
	ret = qcom_scm_qseecom_app_send_phys(km_app_id,
			f->msg_dma + REQ_OFF, 64,
			f->msg_dma + KM_RSP_OFF, KM_RSP_LEN, 0, 0, &r);
	off = krsp[1];
	len = krsp[2];
	dev_info(f->dev,
		 "keymaster cmd 0x205 -> scm=%d result=%lld status=%d offset=%u length=%u\n",
		 ret, r.result, (s32)krsp[0], off, len);
	if (ret || r.result || !len || KM_RSP_OFF + off + len > MSG_SIZE) {
		mutex_unlock(&f->lock);
		return ret ? ret : -EIO;
	}
	blob = kmemdup((u8 *)f->msg + KM_RSP_OFF + off, len, GFP_KERNEL);
	mutex_unlock(&f->lock);
	if (!blob)
		return -ENOMEM;

	ret = fpc_tz_send_buf(f, 3 /*FPC_GROUP_FPCDATA*/, 5 /*FPC_SET_KEY_DATA*/,
			      blob, len);
	kfree(blob);
	dev_info(f->dev, "SET_KEY_DATA (%u bytes) -> %d\n", len, ret);
	return ret;
}

static ssize_t cmd_store(struct device *dev, struct device_attribute *attr,
			 const char *buf, size_t count)
{
	struct fpc_tz *f = dev_get_drvdata(dev);
	u32 group, cmd, arg = 0;
	int ret;

	if (sscanf(buf, "%u:%u:%u", &group, &cmd, &arg) < 2)
		return -EINVAL;
	ret = fpc_tz_send(f, group, cmd, arg);
	return ret ? ret : count;
}
static DEVICE_ATTR_WO(cmd);

static ssize_t reset_store(struct device *dev, struct device_attribute *attr,
			   const char *buf, size_t count)
{
	struct fpc_tz *f = dev_get_drvdata(dev);

	fpc_tz_hw_reset(f);
	return count;
}
static DEVICE_ATTR_WO(reset);

static ssize_t irq_count_show(struct device *dev, struct device_attribute *attr,
			      char *buf)
{
	struct fpc_tz *f = dev_get_drvdata(dev);

	return sysfs_emit(buf, "%d %d\n", atomic_read(&f->irq_count),
			  gpiod_get_value_cansleep(f->irq_gpio));
}
static DEVICE_ATTR_RO(irq_count);

static ssize_t dump_show(struct device *dev, struct device_attribute *attr,
			 char *buf)
{
	struct fpc_tz *f = dev_get_drvdata(dev);
	ssize_t n = 0;
	int i;
	u32 *d = f->data;

	for (i = 0; i < 64; i++)
		n += sysfs_emit_at(buf, n, "%08x%s", d[i], (i % 8 == 7) ? "\n" : " ");
	return n;
}
static DEVICE_ATTR_RO(dump);

/*
 * Goodix Milan-F TA command (reverse-engineered from libgf_hal/libgf_ca):
 * req[4]=1 (const), req[0x10]=cmd_id, req[0x14]=payload phys, req[0x18]=len;
 * response status at req+0x40; payload (~96 B, zeroed) is read back.
 */
static int fpc_tz_gf_send(struct fpc_tz *f, u32 arg0, u32 cmd_id, u32 len)
{
	u32 *m = f->gf_mem;
	s32 *status = (s32 *)((u8 *)f->gf_mem + 0x100);
	struct sglist_info *sgl = (void *)((u8 *)f->gf_mem + 0x780);
	u32 *d = (u32 *)((u8 *)f->gf_mem + 0x200);
	struct qcom_scm_qseecom_raw_resp r = {};
	int ret;

	if (!gf_app_id || !f->gf_mem)
		return -ENODEV;
	if (len > 0x400)
		return -EMSGSIZE;

	mutex_lock(&f->lock);
	memset(f->gf_mem, 0, 0x800);
	m[1] = arg0;				/* arg0 (1 normal, 2 key) */
	m[4] = cmd_id;				/* arg1 = cmd id @0x10 */
	m[5] = lower_32_bits(f->gf_mem_phys + 0x200); /* payload phys @0x14 */
	m[6] = len;				/* @0x18 */
	sgl[0].index_flags = BIT(31) | 0x14;
	sgl[0].size_or_count = len;

	ret = qcom_scm_qseecom_app_send_phys(gf_app_id,
			f->gf_mem_phys, 64, f->gf_mem_phys + 0x100, 64,
			gf_whitelist ? f->gf_mem_phys + 0x780 : 0,
			gf_whitelist ? 4 * sizeof(*sgl) : 0, &r);
	dev_info(f->dev,
		 "gf cmd %u len %u -> scm=%d result=%lld status=%d p0=%08x %08x %08x %08x p60=%08x %08x %08x %08x irqs=%d\n",
		 cmd_id, len, ret, r.result, *status,
		 d[0], d[1], d[2], d[3], d[0x18], d[0x19], d[0x1a], d[0x1b],
		 atomic_read(&f->irq_count));
	mutex_unlock(&f->lock);
	if (ret)
		return ret;
	return r.result ? -EIO : *status;
}

/*
 * Goodix key init (from gf_ca_open_session): fetch a 256-byte keymaster blob
 * (keymaster64 cmd {0x205,0x02}) and hand it to the TA via cmd 109, arg0=2.
 * The TA stays inert until keyed.
 */
static int fpc_tz_gf_setkey(struct fpc_tz *f)
{
	u32 *m = f->gf_mem;
	s32 *status = (s32 *)((u8 *)f->gf_mem + 0x100);
	u8 *km = (u8 *)f->gf_mem + 0x200;	/* keymaster response (256 B) */
	struct qcom_scm_qseecom_raw_resp r = {};
	u32 kmid = km_app_id;
	int ret;

	if (!gf_app_id || !f->gf_mem)
		return -ENODEV;
	if (!kmid) {
		ret = qcom_scm_qseecom_app_get_id("keymaster64", &kmid);
		if (ret || !kmid)
			qcom_scm_qseecom_app_get_id("keymaster", &kmid);
		if (!kmid)
			return -ENODEV;
	}

	mutex_lock(&f->lock);
	/* step 1: keymaster64 cmd {0x205, 0x02} -> 256-byte raw response @ +0x200 */
	memset(f->gf_mem, 0, 0x800);
	m[0] = 0x205;
	m[1] = 0x02;
	ret = qcom_scm_qseecom_app_send_phys(kmid, f->gf_mem_phys, 64,
			f->gf_mem_phys + 0x200, 1024, 0, 0, &r);
	dev_info(f->dev, "gf keymaster(0x205) kmid=%u -> scm=%d result=%lld km[0..3]=%08x %08x %08x %08x\n",
		 kmid, ret, r.result, ((u32 *)km)[0], ((u32 *)km)[1], ((u32 *)km)[2], ((u32 *)km)[3]);
	if (ret || r.result) {
		mutex_unlock(&f->lock);
		return ret ? ret : -EIO;
	}

	/* step 2: hand the 256-byte blob to the TA: arg0=2, cmd 109, len 256 */
	memset(f->gf_mem, 0, 0x40);		/* req header only; keep blob @0x200 */
	memset((u8 *)f->gf_mem + 0x100, 0, 0x40);
	m[1] = 2;				/* arg0 = 2 */
	m[4] = 109;				/* cmd id 0x6d */
	m[5] = lower_32_bits(f->gf_mem_phys + 0x200);
	m[6] = 256;
	ret = qcom_scm_qseecom_app_send_phys(gf_app_id, f->gf_mem_phys, 64,
			f->gf_mem_phys + 0x100, 64, 0, 0, &r);
	dev_info(f->dev, "gf setkey (cmd109 arg0=2) -> scm=%d result=%lld status=%d\n",
		 ret, r.result, *status);
	mutex_unlock(&f->lock);
	if (ret)
		return ret;
	return r.result ? -EIO : *status;
}

static ssize_t gcmd_store(struct device *dev, struct device_attribute *attr,
			  const char *buf, size_t count)
{
	struct fpc_tz *f = dev_get_drvdata(dev);
	u32 cmd_id, len = 100;
	int ret;

	if (sscanf(buf, "%u:%u", &cmd_id, &len) < 1)
		return -EINVAL;
	ret = fpc_tz_gf_send(f, 1, cmd_id, len);
	return ret < 0 ? ret : count;
}
static DEVICE_ATTR_WO(gcmd);

static ssize_t gdump_show(struct device *dev, struct device_attribute *attr,
			  char *buf)
{
	struct fpc_tz *f = dev_get_drvdata(dev);
	u32 *d = (u32 *)((u8 *)f->gf_mem + 0x200);
	ssize_t n = 0;
	int i;

	if (!f->gf_mem)
		return -ENODEV;
	for (i = 0; i < 96; i++)
		n += sysfs_emit_at(buf, n, "%03x: %08x%s", i * 4, d[i],
				   (i % 8 == 7) ? "\n" : " ");
	return n;
}
static DEVICE_ATTR_RO(gdump);

static struct attribute *fpc_tz_attrs[] = {
	&dev_attr_cmd.attr,
	&dev_attr_reset.attr,
	&dev_attr_irq_count.attr,
	&dev_attr_dump.attr,
	&dev_attr_gcmd.attr,
	&dev_attr_gdump.attr,
	NULL
};
ATTRIBUTE_GROUPS(fpc_tz);

static int fpc_tz_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct fpc_tz *f;
	char *list, *tok, *p;
	int ret;

	f = devm_kzalloc(dev, sizeof(*f), GFP_KERNEL);
	if (!f)
		return -ENOMEM;
	f->dev = dev;
	mutex_init(&f->lock);
	platform_set_drvdata(pdev, f);

	f->vdd = devm_regulator_get(dev, "vdd");
	if (IS_ERR(f->vdd))
		return dev_err_probe(dev, PTR_ERR(f->vdd), "vdd\n");
	f->reset = devm_gpiod_get(dev, "reset", GPIOD_OUT_LOW);
	if (IS_ERR(f->reset))
		return dev_err_probe(dev, PTR_ERR(f->reset), "reset gpio\n");
	f->irq_gpio = devm_gpiod_get(dev, "irq", GPIOD_IN);
	if (IS_ERR(f->irq_gpio))
		return dev_err_probe(dev, PTR_ERR(f->irq_gpio), "irq gpio\n");
	f->irq = gpiod_to_irq(f->irq_gpio);
	if (f->irq < 0)
		return dev_err_probe(dev, f->irq, "gpiod_to_irq\n");

	f->se_clk = devm_clk_get_optional(dev, "se");
	if (IS_ERR(f->se_clk))
		return dev_err_probe(dev, PTR_ERR(f->se_clk), "se clk\n");
	if (f->se_clk) {
		int crc;

		if (spi_rate) {
			crc = clk_set_rate(f->se_clk, spi_rate);
			dev_info(dev, "clk_set_rate %u -> %d\n", spi_rate, crc);
		}
		crc = clk_prepare_enable(f->se_clk);
		if (crc)
			dev_err(dev, "SE clk enable: %d\n", crc);
		else
			dev_info(dev, "SE clk enabled, rate %lu\n",
				 clk_get_rate(f->se_clk));
	}
	dev_info(dev, "irq %d, irq line %d before power\n", f->irq,
		 gpiod_get_value_cansleep(f->irq_gpio));

	if (power) {
		ret = regulator_enable(f->vdd);
		if (ret)
			return dev_err_probe(dev, ret, "regulator_enable\n");
		f->powered = true;
		usleep_range(100, 1000);
		fpc_tz_hw_reset(f);
	}

	ret = devm_request_threaded_irq(dev, f->irq, NULL, fpc_tz_irq,
					IRQF_TRIGGER_RISING | IRQF_ONESHOT,
					"fpc_tz", f);
	if (ret)
		dev_err(dev, "request_irq: %d\n", ret);

	f->msg = qcom_scm_qseecom_alloc_image(MSG_SIZE, &f->msg_dma);
	f->data = qcom_scm_qseecom_alloc_image(DATA_SIZE, &f->data_dma);
	if (!f->msg || !f->data)
		return -ENOMEM;
	dev_info(dev, "msg pa %pad data pa %pad\n", &f->msg_dma, &f->data_dma);

	f->gf_mem = qcom_scm_qseecom_tzmem_alloc(0x800, &f->gf_mem_phys);
	if (f->gf_mem)
		dev_info(dev, "gf tzmem pa %pa\n", &f->gf_mem_phys);
	else
		dev_warn(dev, "gf tzmem alloc failed (Goodix path disabled)\n");

	if (gf_key && gf_app_id && f->gf_mem) {
		ret = fpc_tz_gf_setkey(f);
		dev_info(dev, "gf setkey -> %d\n", ret);
	}

	if (!app_id) {
		ret = qcom_scm_qseecom_app_get_id(app_name, &app_id);
		dev_info(dev, "lookup %s: ret=%d id=%u\n", app_name, ret, app_id);
	}

	if (km_init && app_id) {
		ret = fpc_tz_keymaster_init(f);
		dev_info(dev, "keymaster_init -> %d\n", ret);
	}

	if (talk && app_id && seq && *seq) {
		list = kstrdup(seq, GFP_KERNEL);
		p = list;
		while ((tok = strsep(&p, ",")) != NULL) {
			u32 g, c, a = 0;

			if (sscanf(tok, "%u:%u:%u", &g, &c, &a) >= 2)
				fpc_tz_send(f, g, c, a);
		}
		kfree(list);
	}
	return 0;
}

static void fpc_tz_remove(struct platform_device *pdev)
{
	struct fpc_tz *f = platform_get_drvdata(pdev);

	devm_free_irq(&pdev->dev, f->irq, f);
	if (f->powered) {
		gpiod_set_value_cansleep(f->reset, 1);
		regulator_disable(f->vdd);
	}
	if (f->se_clk)
		clk_disable_unprepare(f->se_clk);
	if (f->gf_mem)
		qcom_scm_qseecom_tzmem_free(f->gf_mem);
	if (f->msg)
		qcom_scm_qseecom_free_image(MSG_SIZE, f->msg, f->msg_dma);
	if (f->data)
		qcom_scm_qseecom_free_image(DATA_SIZE, f->data, f->data_dma);
}

static const struct of_device_id fpc_tz_of_match[] = {
	{ .compatible = "fpc,fpc1020-tz" },
	{ }
};
MODULE_DEVICE_TABLE(of, fpc_tz_of_match);

static struct platform_driver fpc_tz_driver = {
	.probe = fpc_tz_probe,
	.remove = fpc_tz_remove,
	.driver = {
		.name = "fpc_tz",
		.of_match_table = fpc_tz_of_match,
		.dev_groups = fpc_tz_groups,
	},
};
module_platform_driver(fpc_tz_driver);

MODULE_DESCRIPTION("FPC fingerprint via QSEE TA (test only)");
MODULE_LICENSE("GPL");
