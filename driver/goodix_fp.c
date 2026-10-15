// SPDX-License-Identifier: GPL-2.0
/*
 * Goodix Milan-F fingerprint char driver for mainline (Poco F1 / sdm845).
 *
 * Port of the downstream MiCode goodix_ta driver (gf_spi.c / platform.c /
 * netlink.c). Like the original it is a *platform* driver: it never touches
 * the SPI serial engine (owned by TrustZone); it only manages the sensor's
 * reset/irq GPIOs, power, the QUP SE clocks the TA needs, and relays IRQs to
 * userspace over netlink. The fingerprint TA in QSEE does the actual SPI.
 *
 * /dev/goodix_fp ioctls match the vendor HAL (libgf_hal.so):
 *   GF_IOC_RESET, GF_IOC_ENABLE/DISABLE_IRQ, GF_IOC_ENABLE/DISABLE_SPI_CLK,
 *   GF_IOC_ENABLE/DISABLE_POWER, GF_IOC_CHIP_INFO, ...
 */
#include <linux/clk.h>
#include <linux/ctype.h>
#include <linux/delay.h>
#include <linux/kstrtox.h>
#include <linux/fs.h>
#include <linux/gpio/consumer.h>
#include <linux/interrupt.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/regulator/consumer.h>
#include <linux/uaccess.h>
#include <net/sock.h>
#include <linux/dma-mapping.h>
#include <linux/firmware/qcom/qcom_scm.h>
#include <linux/unaligned.h>

#define GF_IOC_MAGIC		'g'
#define GF_IOC_INIT		_IOR(GF_IOC_MAGIC, 0, u8)
#define GF_IOC_EXIT		_IO(GF_IOC_MAGIC, 1)
#define GF_IOC_RESET		_IO(GF_IOC_MAGIC, 2)
#define GF_IOC_ENABLE_IRQ	_IO(GF_IOC_MAGIC, 3)
#define GF_IOC_DISABLE_IRQ	_IO(GF_IOC_MAGIC, 4)
#define GF_IOC_ENABLE_SPI_CLK	_IOW(GF_IOC_MAGIC, 5, u32)
#define GF_IOC_DISABLE_SPI_CLK	_IO(GF_IOC_MAGIC, 6)
#define GF_IOC_ENABLE_POWER	_IO(GF_IOC_MAGIC, 7)
#define GF_IOC_DISABLE_POWER	_IO(GF_IOC_MAGIC, 8)
#define GF_IOC_ENTER_SLEEP_MODE	_IO(GF_IOC_MAGIC, 10)
#define GF_IOC_GET_FW_INFO	_IOR(GF_IOC_MAGIC, 11, u8)
#define GF_IOC_REMOVE		_IO(GF_IOC_MAGIC, 12)

struct gf_ioc_chip_info {
	u8 vendor_id;
	u8 mode;
	u8 operation;
	u8 reserved[5];
};
#define GF_IOC_CHIP_INFO	_IOW(GF_IOC_MAGIC, 13, struct gf_ioc_chip_info)

/* netlink, matching the vendor HAL */
#define GF_NETLINK_UNIT		25
#define GF_NET_EVENT_IRQ	1
#define GF_NET_EVENT_FB_BLACK	2
#define GF_NET_EVENT_FB_UNBLACK	3

/* Armed-capture mode. TEST frame grabs auto-stop once a frame carries pixels;
 * ENROLL/AUTH stay armed across touches because the TA accumulates/matches
 * internally over several presses and reports progress per GF_CMD_IRQ pull. */
enum gf_cap_mode { GF_CAP_NONE, GF_CAP_TEST, GF_CAP_ENROLL, GF_CAP_AUTH };

/* One GF_CMD_IRQ(1016) pull, captured for offline result-field discovery.
 * Recorded ON CHANGE only, so a multi-second press keeps its transitions
 * (enroll-remaining decrement, match result) instead of wrapping on steady state. */
struct gf_pull_rec {
	u32 irq_type, op, step;
	s32 status;
	u32 w[16];		/* irq_buf[0x60..0x9f] — candidate result words */
};

/* Header snapshot latched per distinct (irq_type, op, step): the result field
 * could be anywhere in the command header, so keep the first 0x200 bytes of the
 * first pull seen in each state. Dumped via the 'snaps' bin attr. */
struct gf_hdr_snap {
	u32 irq_type, op, step;
	bool used;
	u8 hdr[0x200];
};

struct gf_dev {
	struct device *dev;
	struct miscdevice misc;
	struct clk *core_clk;
	struct clk *iface_clk;
	struct gpio_desc *reset_gpio;
	struct gpio_desc *irq_gpio;
	struct regulator *vdd;
	struct sock *nl_sk;
	int irq;
	int nl_pid;
	bool irq_enabled;
	bool clk_enabled;
	bool power_on;
	struct mutex lock;	/* serialises ioctl state */
	struct mutex ta_lock;	/* serialises gf_mem/gf_pay/gf_img TA traffic */
	void *gf_mem;		/* tzmem for gfber cmd+resp */
	phys_addr_t gf_mem_phys;
	void *gf_pay;		/* SEPARATE tzmem for payload (TA requires distinct buf) */
	phys_addr_t gf_pay_phys;
	void *gf_img;		/* big contiguous buffer (0x37000) for GF_CMD_IRQ(1016) frame */
	dma_addr_t gf_img_dma;
	void *km_mem;		/* dma-coherent for keymaster */
	dma_addr_t km_dma;
	u8 frame[19008];	/* last captured frame (88*108*2, u16) */
	u32 frame_irq, frame_op, frame_nz;
	bool capture_armed;	/* pull a frame on each GPIO IRQ */
	enum gf_cap_mode cap_mode;
	int cap_pulls;
	u8 gpay_seed[0x800];	/* staged payload for gcmd (set via gpay sysfs) */
	u32 gpay_len;
	struct gf_pull_rec trace[96];	/* ring of CHANGED GF_CMD_IRQ pulls */
	u32 trace_head, trace_n;
	struct gf_hdr_snap snaps[8];	/* one header per distinct (irq_type,op,step) */
};
#define GF_IMG_SIZE	0x37000
#define GF_IRQ_BUFLEN	0x36a20
#define GF_FRAME_OFF	0xb178		/* op39 real-time frame #1 at irq_buf+0xb178 */
#define GF_FRAME_LEN	19008

/* gfber command groups (send_buf[0x04]) and the sub-commands we drive. */
#define GF_GRP_MAIN	1	/* init / capture / enroll / auth */
#define GF_GRP_KEY	2	/* setkey */
#define GF_GRP_TEST	3	/* version / real-time-data / test enroll+auth */
#define GF_GRP_DUMP	4

/* grp1 (main) sub-commands */
#define GF_CMD_DETECT_SENSOR	1000
#define GF_CMD_INIT		1001
#define GF_CMD_DOWNLOAD_FW	1003
#define GF_CMD_DOWNLOAD_CFG	1004
#define GF_CMD_INIT_FINISHED	1005
#define GF_CMD_PRE_ENROLL	1006	/* grp1, len104 */
#define GF_CMD_ENROLL		1007	/* grp1, len176, payload[0x60]=gid [0x69..0xb0]=HAT */
#define GF_CMD_AUTHENTICATE	1010	/* grp1, len120, [0x60]=op_id [0x68]=chal [0x70]=screen */
#define GF_CMD_IRQ		1016	/* grp1, big image buffer — IRQ frame/result pull */
#define GF_CMD_CAMERA_CAPTURE	1021

/* grp3 (test) sub-commands */
#define GF_CMD_TEST_PRE_GET_VERSION	1036
#define GF_CMD_TEST_GET_VERSION		1037
#define GF_CMD_TEST_ENROLL		1060	/* grp3, len96, no HAT (FRR/FAR route) */
#define GF_CMD_TEST_AUTHENTICATE	1061	/* grp3, len120, [0x60]=op_id [0x68]=chal */
#define GF_CMD_TEST_REAL_TIME_DATA	1067

static struct gf_dev *g_gf;

static uint gf_app_id;
module_param(gf_app_id, uint, 0644);
MODULE_PARM_DESC(gf_app_id, "gfber QSEE app id (from qseecom_load)");
static uint km_app_id = 1;
module_param(km_app_id, uint, 0644);
MODULE_PARM_DESC(km_app_id, "keymaster64 app id (bootloader, usually 1)");
static uint trace_wmask = 0xffff;
module_param(trace_wmask, uint, 0644);
MODULE_PARM_DESC(trace_wmask, "bitmask of irq_buf words w[0..15] that count as a trace change (mask out a counter/timestamp word to stop the ring wrapping)");

static void gf_netlink_send(struct gf_dev *gf, u8 event)
{
	struct sk_buff *skb;
	struct nlmsghdr *nlh;

	if (!gf->nl_sk || gf->nl_pid <= 0)
		return;
	skb = nlmsg_new(1, GFP_ATOMIC);
	if (!skb)
		return;
	nlh = nlmsg_put(skb, 0, 0, 0, 1, 0);
	if (!nlh) {
		nlmsg_free(skb);
		return;
	}
	*(u8 *)nlmsg_data(nlh) = event;
	nlmsg_unicast(gf->nl_sk, skb, gf->nl_pid);
}

static void gf_nl_recv(struct sk_buff *skb)
{
	struct nlmsghdr *nlh = nlmsg_hdr(skb);

	if (g_gf)
		g_gf->nl_pid = nlh->nlmsg_pid;	/* learn userspace pid */
}

static int gf_pull_irq(struct gf_dev *gf);

static irqreturn_t gf_irq(int irq, void *p)
{
	struct gf_dev *gf = p;

	/* Threaded handler. On a real sensor IRQ, pull the frame/result via
	 * GF_CMD_IRQ. TEST frame grabs stop once a frame has pixels; ENROLL/AUTH
	 * stay armed (the TA accumulates/matches across presses). */
	if (gf->capture_armed && gf->gf_img) {
		mutex_lock(&gf->ta_lock);
		gf_pull_irq(gf);
		gf->cap_pulls++;
		if ((gf->cap_mode == GF_CAP_TEST && gf->frame_nz > 64) ||
		    gf->cap_pulls > 1000) {
			gf->capture_armed = false;
			dev_info(gf->dev, "CAPTURE stop mode=%d pulls=%d irq=0x%x op=%u nz=%u\n",
				 gf->cap_mode, gf->cap_pulls, gf->frame_irq,
				 gf->frame_op, gf->frame_nz);
		}
		mutex_unlock(&gf->ta_lock);
	}
	gf_netlink_send(gf, GF_NET_EVENT_IRQ);
	return IRQ_HANDLED;
}

static void gf_hw_reset(struct gf_dev *gf, unsigned int delay_ms)
{
	gpiod_set_value_cansleep(gf->reset_gpio, 1);	/* assert (active low) */
	mdelay(3);
	gpiod_set_value_cansleep(gf->reset_gpio, 0);	/* deassert */
	mdelay(delay_ms);
}

static int gf_clk_enable(struct gf_dev *gf)
{
	int rc;

	if (gf->clk_enabled)
		return 0;
	rc = clk_prepare_enable(gf->core_clk);
	if (rc)
		return rc;
	rc = clk_prepare_enable(gf->iface_clk);
	if (rc) {
		clk_disable_unprepare(gf->core_clk);
		return rc;
	}
	gf->clk_enabled = true;
	return 0;
}

static void gf_clk_disable(struct gf_dev *gf)
{
	if (!gf->clk_enabled)
		return;
	clk_disable_unprepare(gf->iface_clk);
	clk_disable_unprepare(gf->core_clk);
	gf->clk_enabled = false;
}

static void gf_irq_set(struct gf_dev *gf, bool on)
{
	if (on && !gf->irq_enabled) {
		enable_irq(gf->irq);
		gf->irq_enabled = true;
	} else if (!on && gf->irq_enabled) {
		disable_irq(gf->irq);
		gf->irq_enabled = false;
	}
}

/* ---- TrustZone fingerprint TA (gfber) command path ---------------------- *
 * TRUE wire format (RE'd from libgf_ca gf_ca_invoke_command, 2026-10-08):
 *   req 64B at gf_mem+0: [0x04]=cmd_grp (1=main/2=user/3=test/4=dump), [0x10]=
 *   arg1 (the GF_CMD_* sub-command), [0x14]=payload phys, [0x18]=payload len.
 *   The TA writes its response at req+0x40 (status s32 @ +0x40), and writes
 *   response DATA into the payload buffer at [0x14]. The payload MUST be a
 *   physically SEPARATE tzmem buffer from the cmd/resp buffer (the TA no-ops
 *   if payload overlaps the cmd buffer — confirmed vs the shim's h->aux path).
 * LOCKING: callers must hold gf->ta_lock (shared gf_mem/gf_pay/gf_img). The
 *   threaded IRQ handler and every sysfs store take it before calling these.
 */
static int gf_ta_send_io(struct gf_dev *gf, u32 cmd_grp, u32 arg1, u32 len,
			 const void *in, u32 inlen)
{
	u32 *m = gf->gf_mem;
	s32 *status = (s32 *)((u8 *)gf->gf_mem + 0x40);	/* TA writes resp @ +0x40 */
	struct qcom_scm_qseecom_raw_resp r = {};
	int ret;

	if (!gf_app_id || !gf->gf_mem || !gf->gf_pay)
		return -ENODEV;
	if (len > 0x800 || inlen > 0x800)
		return -EMSGSIZE;
	memset(gf->gf_mem, 0, 0x80);			/* req(0x40) + resp(0x40) */
	memset(gf->gf_pay, 0, 0x800);			/* SEPARATE payload buffer */
	if (in && inlen)
		memcpy(gf->gf_pay, in, inlen);
	m[1] = cmd_grp;					/* [0x04] */
	m[4] = arg1;					/* [0x10] */
	m[5] = lower_32_bits(gf->gf_pay_phys);		/* [0x14] payload phys (separate) */
	m[6] = len;					/* [0x18] */
	ret = qcom_scm_qseecom_app_send_phys(gf_app_id, gf->gf_mem_phys, 64,
			gf->gf_mem_phys + 0x40, 64, 0, 0, &r);
	if (ret)
		return ret;
	return r.result ? -EIO : *status;
}

static int gf_ta_send(struct gf_dev *gf, u32 cmd_grp, u32 arg1, u32 len)
{
	return gf_ta_send_io(gf, cmd_grp, arg1, len, NULL, 0);
}

/* Send using the big gf_img buffer as payload (phys passed directly, no bounce).
 * Caller seeds gf_img; this does NOT clear it. For GF_CMD_IRQ(1016) frame pulls.
 * Caller holds gf->ta_lock. */
static int gf_ta_img(struct gf_dev *gf, u32 cmd_grp, u32 arg1, u32 len)
{
	u32 *m = gf->gf_mem;
	s32 *status = (s32 *)((u8 *)gf->gf_mem + 0x40);
	struct qcom_scm_qseecom_raw_resp r = {};
	int ret;

	if (!gf_app_id || !gf->gf_mem || !gf->gf_img)
		return -ENODEV;
	if (len > GF_IMG_SIZE)
		return -EMSGSIZE;
	memset(gf->gf_mem, 0, 0x80);
	m[1] = cmd_grp;
	m[4] = arg1;
	m[5] = lower_32_bits(gf->gf_img_dma);	/* [0x14] payload phys = big buffer */
	m[6] = len;
	ret = qcom_scm_qseecom_app_send_phys(gf_app_id, gf->gf_mem_phys, 64,
			gf->gf_mem_phys + 0x40, 64, 0, 0, &r);
	if (ret)
		return ret;
	return r.result ? -EIO : *status;
}

/* Latch the header of the first pull seen in each distinct (irq_type,op,step). */
static void gf_snap_header(struct gf_dev *gf, u32 irq_type, u32 op, u32 step,
			   const u8 *b)
{
	u32 i;

	for (i = 0; i < ARRAY_SIZE(gf->snaps); i++) {
		struct gf_hdr_snap *s = &gf->snaps[i];

		if (s->used && s->irq_type == irq_type && s->op == op &&
		    s->step == step)
			return;				/* already captured */
		if (!s->used) {
			s->irq_type = irq_type;
			s->op = op;
			s->step = step;
			memcpy(s->hdr, b, sizeof(s->hdr));
			s->used = true;
			return;
		}
	}
}

/* Record a GF_CMD_IRQ pull — but only when it DIFFERS from the previous record,
 * so a multi-second press keeps its transitions instead of wrapping on the
 * steady state. Returns true on a change (caller logs it). */
static bool gf_trace_push(struct gf_dev *gf, u32 irq_type, u32 op, u32 step,
			  s32 status, const u8 *b)
{
	u32 n = ARRAY_SIZE(gf->trace);
	struct gf_pull_rec *rec = &gf->trace[gf->trace_head];
	struct gf_pull_rec cur = { irq_type, op, step, status };
	int i;

	for (i = 0; i < 16; i++)
		cur.w[i] = get_unaligned_le32(b + 0x60 + i * 4);
	gf_snap_header(gf, irq_type, op, step, b);

	if (gf->trace_n) {
		struct gf_pull_rec *last = &gf->trace[(gf->trace_head + n - 1) % n];
		bool changed = last->irq_type != cur.irq_type || last->op != cur.op ||
			       last->step != cur.step || last->status != cur.status;

		for (i = 0; i < 16 && !changed; i++)
			if ((trace_wmask >> i) & 1 && last->w[i] != cur.w[i])
				changed = true;
		if (!changed)
			return false;			/* unchanged (under mask) — skip */
	}
	*rec = cur;
	gf->trace_head = (gf->trace_head + 1) % n;
	if (gf->trace_n < n)
		gf->trace_n++;
	return true;
}

/* GF_CMD_IRQ(1016): ack an IRQ and pull the frame/result. On an IMAGE irq
 * (op 39) copy frame #1 out. Each internal send is recorded to the trace ring.
 * Caller holds gf->ta_lock. */
static int gf_pull_irq(struct gf_dev *gf)
{
	u8 *b = gf->gf_img;
	u32 irq_type, op, step;
	int ret, i;

	if (!b)
		return -ENODEV;
	memset(b, 0, GF_IMG_SIZE);
	put_unaligned_le32(0x02000000, b + 0x367e1);	/* HAL seeds (hal_milan_f_series_irq) */
	put_unaligned_le32(0x200, b + 0x36810);
	put_unaligned_le32(1, b + 0x36a18);		/* step = 1 */
	irq_type = 0;
	for (i = 0; i < 6; i++) {
		ret = gf_ta_img(gf, GF_GRP_MAIN, GF_CMD_IRQ, GF_IRQ_BUFLEN);
		irq_type = get_unaligned_le32(b + 0x60);
		op = get_unaligned_le32(b + 0x64);
		step = get_unaligned_le32(b + 0x36a18);
		if (gf_trace_push(gf, irq_type, op, step, ret, b))
			dev_info(gf->dev, "GF_CMD_IRQ -> ret=%d irq_type=0x%x op=%u step=%u w=%08x %08x %08x %08x\n",
				 ret, irq_type, op, step,
				 get_unaligned_le32(b + 0x68), get_unaligned_le32(b + 0x6c),
				 get_unaligned_le32(b + 0x70), get_unaligned_le32(b + 0x74));
		if (ret)
			return ret;
		{	/* count nonzero in the frame region */
			u32 j, nz = 0;
			for (j = 0; j < GF_FRAME_LEN; j++)
				if (b[GF_FRAME_OFF + j]) nz++;
			gf->frame_nz = nz;
		}
		memcpy(gf->frame, b + GF_FRAME_OFF, GF_FRAME_LEN);
		gf->frame_irq = irq_type;
		gf->frame_op = op;
		if (step != 4 && step != 5)
			break;
		/* resend with buffer untouched */
	}
	return irq_type;
}

static int gf_ta_setkey(struct gf_dev *gf)
{
	u32 *km = gf->km_mem;			/* dma buffer for keymaster */
	struct qcom_scm_qseecom_raw_resp r = {};
	u32 kmid = 0;
	u32 *krsp = (u32 *)((u8 *)gf->km_mem + 0x1000);
	int ret;

	if (!gf->km_mem || !gf->gf_mem)
		return -ENODEV;
	/* always resolve keymaster64 id; the bootloader-assigned id varies */
	ret = qcom_scm_qseecom_app_get_id("keymaster64", &kmid);
	if (ret || !kmid)
		qcom_scm_qseecom_app_get_id("keymaster", &kmid);
	if (!kmid)
		kmid = km_app_id;
	dev_info(gf->dev, "keymaster app id=%u\n", kmid);

	/* keymaster64 cmd {0x205, 0x02} via dma buffer -> raw response */
	memset(gf->km_mem, 0, 8192);
	km[0] = 0x205;
	km[1] = 0x02;
	ret = qcom_scm_qseecom_app_send_phys(kmid, gf->km_dma, 64,
			gf->km_dma + 0x1000, 1024, 0, 0, &r);
	dev_info(gf->dev, "keymaster(0x205) -> scm=%d result=%lld km_rsp=%08x %08x %08x %08x %08x %08x\n",
		 ret, r.result, krsp[0], krsp[1], krsp[2], krsp[3], krsp[4], krsp[5]);
	if (ret || r.result)
		return ret ? ret : -EIO;

	/* set key: group 2, sub-cmd 109, payload = raw 256-B keymaster response */
	ret = gf_ta_send_io(gf, GF_GRP_KEY, 109, 256,
			    (u8 *)gf->km_mem + 0x1000, 256);
	dev_info(gf->dev, "setkey (cmd2 arg109) -> status=%d\n", ret);
	return ret;
}

static void gf_log_step(struct gf_dev *gf, const char *nm, u32 arg1, int ret)
{
	u32 *d = gf->gf_pay;

	dev_info(gf->dev, "%-18s (a%u) -> status=%d  pay=%08x %08x %08x %08x\n",
		 nm, arg1, ret, d ? d[0] : 0, d ? d[1] : 0, d ? d[2] : 0, d ? d[3] : 0);
}

/* Full HAL-order init (gf_hal_open): power, clk, reset, key, then the real
 * GF_CMD init sequence: DETECT_SENSOR -> INIT -> INIT_FINISHED. DOWNLOAD_FW/CFG
 * are folded into INIT+OTP on Milan-F (not sent). Caller holds gf->ta_lock. */
static int gf_ta_init(struct gf_dev *gf)
{
	int ret;

	if (gf->vdd && !gf->power_on && !regulator_enable(gf->vdd))
		gf->power_on = true;
	gf_clk_enable(gf);
	gf_hw_reset(gf, 10);
	gf_irq_set(gf, true);

	ret = gf_ta_setkey(gf);
	if (ret)
		dev_warn(gf->dev, "setkey returned %d (continuing)\n", ret);

	/* Fable recipe: per-cmd lengths; DOWNLOAD_FW/CFG folded into INIT+OTP. */
	ret = gf_ta_send(gf, GF_GRP_MAIN, GF_CMD_DETECT_SENSOR, 356);
	gf_log_step(gf, "DETECT_SENSOR", GF_CMD_DETECT_SENSOR, ret);
	ret = gf_ta_send(gf, GF_GRP_MAIN, GF_CMD_INIT, 168);
	gf_log_step(gf, "INIT", GF_CMD_INIT, ret);
	ret = gf_ta_send(gf, GF_GRP_MAIN, GF_CMD_INIT_FINISHED, 100);
	gf_log_step(gf, "INIT_FINISHED", GF_CMD_INIT_FINISHED, ret);
	return ret;
}

static ssize_t ginit_store(struct device *dev, struct device_attribute *a,
			   const char *buf, size_t n)
{
	struct gf_dev *gf = dev_get_drvdata(dev);
	int ret;

	mutex_lock(&gf->ta_lock);
	ret = gf_ta_init(gf);
	mutex_unlock(&gf->ta_lock);
	return ret < 0 ? ret : n;
}
static DEVICE_ATTR_WO(ginit);

/* "arg1[:len[:grp]]" (grp defaults 1, len 256). Uses the staged gpay payload
 * (set via the gpay sysfs) when present, else a zeroed payload. */
static ssize_t gcmd_store(struct device *dev, struct device_attribute *a,
			  const char *buf, size_t n)
{
	struct gf_dev *gf = dev_get_drvdata(dev);
	u32 *d = gf->gf_pay;
	u32 arg1, len = 256, grp = 1;
	int ret;

	if (sscanf(buf, "%u:%u:%u", &arg1, &len, &grp) < 1)
		return -EINVAL;
	mutex_lock(&gf->ta_lock);
	if (gf->gpay_len)
		ret = gf_ta_send_io(gf, grp, arg1, len, gf->gpay_seed, gf->gpay_len);
	else
		ret = gf_ta_send(gf, grp, arg1, len);
	dev_info(gf->dev, "gcmd grp%u a%u len%u (pay%u) -> status=%d  pay=%08x %08x %08x %08x\n",
		 grp, arg1, len, gf->gpay_len, ret, d[0], d[1], d[2], d[3]);
	mutex_unlock(&gf->ta_lock);
	return ret < 0 ? ret : n;
}
static DEVICE_ATTR_WO(gcmd);

/* Stage the payload bytes for the next gcmd. Format: "OFF HEX..." pokes bytes at
 * byte-offset OFF (e.g. "60 00000000" sets a u32 at +0x60); "clear" zeroes it.
 * This lets a probe set group_id/op_id/challenge/HAT at the right offsets. */
static ssize_t gpay_store(struct device *dev, struct device_attribute *a,
			  const char *buf, size_t n)
{
	struct gf_dev *gf = dev_get_drvdata(dev);
	unsigned int off, i = 0;
	const char *p;

	if (!strncmp(buf, "clear", 5)) {
		memset(gf->gpay_seed, 0, sizeof(gf->gpay_seed));
		gf->gpay_len = 0;
		return n;
	}
	if (sscanf(buf, "%x", &off) != 1)
		return -EINVAL;
	p = strchr(buf, ' ');
	if (!p)
		return -EINVAL;
	while (*p == ' ')
		p++;
	/* consume hex nibble pairs */
	while (p[0] && p[1] && isxdigit(p[0]) && isxdigit(p[1])) {
		u8 byte;
		char pair[3] = { p[0], p[1], 0 };

		if (kstrtou8(pair, 16, &byte))
			break;
		if (off + i >= sizeof(gf->gpay_seed))
			break;
		gf->gpay_seed[off + i] = byte;
		i++;
		p += 2;
	}
	if (off + i > gf->gpay_len)
		gf->gpay_len = off + i;
	dev_info(gf->dev, "gpay off=0x%x +%u bytes -> seed_len=%u\n", off, i, gf->gpay_len);
	return n;
}
static DEVICE_ATTR_WO(gpay);

/* write: pull one IRQ/frame via GF_CMD_IRQ(1016) into gf->frame. */
static ssize_t capture_store(struct device *dev, struct device_attribute *a,
			     const char *buf, size_t n)
{
	struct gf_dev *gf = dev_get_drvdata(dev);
	int ret;

	mutex_lock(&gf->ta_lock);
	ret = gf_pull_irq(gf);
	mutex_unlock(&gf->ta_lock);
	dev_info(gf->dev, "capture -> irq_type=0x%x op=%u\n", ret, gf->frame_op);
	return ret < 0 ? ret : n;
}
static DEVICE_ATTR_WO(capture);

/* Arm an armed-capture mode. Clears the trace ring and pull counter. */
static void gf_arm(struct gf_dev *gf, enum gf_cap_mode mode)
{
	gf->cap_pulls = 0;
	gf->frame_nz = 0;
	gf->trace_head = 0;
	gf->trace_n = 0;
	memset(gf->snaps, 0, sizeof(gf->snaps));
	gf->cap_mode = mode;
	gf->capture_armed = true;
}

/* write 1: arm real-time-data (grp3/1067) TEST frame capture-on-IRQ until a
 * frame has pixels. write 0: disarm. read: armed/pulls/op/irq/nz. */
static ssize_t autocap_store(struct device *dev, struct device_attribute *a,
			     const char *buf, size_t n)
{
	struct gf_dev *gf = dev_get_drvdata(dev);

	mutex_lock(&gf->ta_lock);
	if (buf[0] == '0') {
		gf->capture_armed = false;
		gf->cap_mode = GF_CAP_NONE;
	} else {
		gf_ta_send(gf, GF_GRP_TEST, GF_CMD_TEST_REAL_TIME_DATA, 96);
		gf_arm(gf, GF_CAP_TEST);
	}
	mutex_unlock(&gf->ta_lock);
	dev_info(gf->dev, "autocap armed=%d\n", gf->capture_armed);
	return n;
}
static ssize_t autocap_show(struct device *dev, struct device_attribute *a, char *buf)
{
	struct gf_dev *gf = dev_get_drvdata(dev);

	return sysfs_emit(buf, "armed=%d mode=%d pulls=%d op=%u irq=0x%x nz=%u\n",
			  gf->capture_armed, gf->cap_mode, gf->cap_pulls,
			  gf->frame_op, gf->frame_irq, gf->frame_nz);
}
static DEVICE_ATTR_RW(autocap);

/* write 1: TEST enroll (grp3/1060, no HAT) + arm ENROLL mode (stays armed over
 * presses). write 7:<hat_hex>: real enroll (grp1/1007) with the staged gpay HAT.
 * Read the dmesg GF_CMD_IRQ trace (or the trace sysfs) for enroll progress. */
static ssize_t enroll_store(struct device *dev, struct device_attribute *a,
			    const char *buf, size_t n)
{
	struct gf_dev *gf = dev_get_drvdata(dev);
	int ret;

	mutex_lock(&gf->ta_lock);
	if (buf[0] == '7') {
		/* real enroll: payload staged via gpay ([0x60]=gid,[0x69..]=HAT) */
		ret = gf->gpay_len
		    ? gf_ta_send_io(gf, GF_GRP_MAIN, GF_CMD_ENROLL, 176,
				    gf->gpay_seed, gf->gpay_len)
		    : gf_ta_send(gf, GF_GRP_MAIN, GF_CMD_ENROLL, 176);
		dev_info(gf->dev, "ENROLL(grp1/1007) -> status=%d\n", ret);
	} else {
		ret = gf_ta_send(gf, GF_GRP_TEST, GF_CMD_TEST_ENROLL, 96);
		dev_info(gf->dev, "TEST_ENROLL(grp3/1060) -> status=%d\n", ret);
	}
	gf_arm(gf, GF_CAP_ENROLL);
	mutex_unlock(&gf->ta_lock);
	return ret < 0 ? ret : n;
}
static DEVICE_ATTR_WO(enroll);

/* write "op_id[:chal_lo[:chal_hi]]": TEST authenticate (grp3/1061) with op_id at
 * payload[0x60] and the 8-byte challenge at [0x68] + arm AUTH mode.
 * write "r:op_id:...": real authenticate (grp1/1010). Defaults 0/0. */
static ssize_t authenticate_store(struct device *dev, struct device_attribute *a,
				  const char *buf, size_t n)
{
	struct gf_dev *gf = dev_get_drvdata(dev);
	u8 pay[120];
	u32 op_id = 0, chal_lo = 0, chal_hi = 0, grp = GF_GRP_TEST, arg = GF_CMD_TEST_AUTHENTICATE;
	const char *p = buf;
	int ret;

	if (*p == 'r') {			/* real authenticate path */
		grp = GF_GRP_MAIN;
		arg = GF_CMD_AUTHENTICATE;
		p = strchr(buf, ':');
		p = p ? p + 1 : "";
	}
	sscanf(p, "%u:%u:%u", &op_id, &chal_lo, &chal_hi);
	memset(pay, 0, sizeof(pay));
	put_unaligned_le32(op_id, pay + 0x60);
	put_unaligned_le32(chal_lo, pay + 0x68);
	put_unaligned_le32(chal_hi, pay + 0x6c);
	mutex_lock(&gf->ta_lock);
	ret = gf_ta_send_io(gf, grp, arg, sizeof(pay), pay, sizeof(pay));
	dev_info(gf->dev, "AUTH grp%u a%u op_id=%u chal=%08x%08x -> status=%d\n",
		 grp, arg, op_id, chal_hi, chal_lo, ret);
	gf_arm(gf, GF_CAP_AUTH);
	mutex_unlock(&gf->ta_lock);
	return ret < 0 ? ret : n;
}
static DEVICE_ATTR_WO(authenticate);

/* read: the recent GF_CMD_IRQ pull trace (for result-field discovery). */
static ssize_t trace_show(struct device *dev, struct device_attribute *a, char *buf)
{
	struct gf_dev *gf = dev_get_drvdata(dev);
	ssize_t o = 0;
	u32 i, idx;

	mutex_lock(&gf->ta_lock);
	for (i = 0; i < gf->trace_n; i++) {
		struct gf_pull_rec *r;

		idx = (gf->trace_head + ARRAY_SIZE(gf->trace) - gf->trace_n + i)
			% ARRAY_SIZE(gf->trace);
		r = &gf->trace[idx];
		o += sysfs_emit_at(buf, o,
			"irq=0x%02x op=%u step=%u st=%d w=%08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x\n",
			r->irq_type, r->op, r->step, r->status,
			r->w[0], r->w[1], r->w[2], r->w[3], r->w[4], r->w[5], r->w[6], r->w[7],
			r->w[8], r->w[9], r->w[10], r->w[11], r->w[12], r->w[13], r->w[14], r->w[15]);
	}
	mutex_unlock(&gf->ta_lock);
	return o;
}
static DEVICE_ATTR_RO(trace);

/* read: the last captured raw frame region (dumps gf_img, GF_IRQ_BUFLEN). */
static ssize_t frame_read(struct file *f, struct kobject *kobj,
			  const struct bin_attribute *attr, char *buf,
			  loff_t off, size_t count)
{
	struct device *dev = kobj_to_dev(kobj);
	struct gf_dev *gf = dev_get_drvdata(dev);

	if (!gf->gf_img)
		return 0;
	return memory_read_from_buffer(buf, count, &off, gf->gf_img, GF_IRQ_BUFLEN);
}
static BIN_ATTR_RO(frame, GF_IRQ_BUFLEN);

/* read: the latched per-(irq_type,op,step) header snapshots (8 * sizeof snap). */
static ssize_t snaps_read(struct file *f, struct kobject *kobj,
			  const struct bin_attribute *attr, char *buf,
			  loff_t off, size_t count)
{
	struct device *dev = kobj_to_dev(kobj);
	struct gf_dev *gf = dev_get_drvdata(dev);

	return memory_read_from_buffer(buf, count, &off, gf->snaps,
				       sizeof(gf->snaps));
}
static BIN_ATTR_RO(snaps, sizeof(((struct gf_dev *)0)->snaps));

static ssize_t gdump_show(struct device *dev, struct device_attribute *a,
			  char *buf)
{
	struct gf_dev *gf = dev_get_drvdata(dev);
	u32 *d = gf->gf_pay;
	ssize_t o = 0;
	int i;

	if (!d)
		return 0;
	for (i = 0; i < 96; i++)
		o += sysfs_emit_at(buf, o, "%03x: %08x%s", i * 4, d[i],
				   (i % 8 == 7) ? "\n" : " ");
	return o;
}
static DEVICE_ATTR_RO(gdump);

static long gf_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct gf_dev *gf = filp->private_data;
	int rc = 0;

	if (_IOC_TYPE(cmd) != GF_IOC_MAGIC)
		return -ENOTTY;

	mutex_lock(&gf->lock);
	switch (cmd) {
	case GF_IOC_INIT: {
		u8 val = 0;	/* netlink-enabled marker for the HAL */

		if (copy_to_user((void __user *)arg, &val, 1))
			rc = -EFAULT;
		break;
	}
	case GF_IOC_EXIT:
	case GF_IOC_REMOVE:
		break;
	case GF_IOC_RESET:
		gf_hw_reset(gf, 3);
		break;
	case GF_IOC_ENABLE_IRQ:
		gf_irq_set(gf, true);
		break;
	case GF_IOC_DISABLE_IRQ:
		gf_irq_set(gf, false);
		break;
	case GF_IOC_ENABLE_SPI_CLK:
		rc = gf_clk_enable(gf);
		break;
	case GF_IOC_DISABLE_SPI_CLK:
		gf_clk_disable(gf);
		break;
	case GF_IOC_ENABLE_POWER:
		if (gf->vdd && !gf->power_on) {
			rc = regulator_enable(gf->vdd);
			if (!rc)
				gf->power_on = true;
		}
		break;
	case GF_IOC_DISABLE_POWER:
		if (gf->vdd && gf->power_on) {
			regulator_disable(gf->vdd);
			gf->power_on = false;
		}
		break;
	case GF_IOC_ENTER_SLEEP_MODE:
		break;
	case GF_IOC_CHIP_INFO: {
		struct gf_ioc_chip_info info;

		if (copy_from_user(&info, (void __user *)arg, sizeof(info)))
			rc = -EFAULT;
		/* vendor id resolution is a TA op; report unknown here */
		break;
	}
	case GF_IOC_GET_FW_INFO: {
		u8 val = 0;

		if (copy_to_user((void __user *)arg, &val, 1))
			rc = -EFAULT;
		break;
	}
	default:
		rc = -EINVAL;
	}
	mutex_unlock(&gf->lock);
	return rc;
}

static int gf_open(struct inode *ino, struct file *filp)
{
	filp->private_data = g_gf;
	return 0;
}

static int gf_release(struct inode *ino, struct file *filp)
{
	return 0;
}

static const struct file_operations gf_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = gf_ioctl,
	.compat_ioctl = gf_ioctl,
	.open = gf_open,
	.release = gf_release,
};

static int gf_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct netlink_kernel_cfg cfg = { .input = gf_nl_recv };
	struct gf_dev *gf;
	int rc;

	gf = devm_kzalloc(dev, sizeof(*gf), GFP_KERNEL);
	if (!gf)
		return -ENOMEM;
	gf->dev = dev;
	mutex_init(&gf->lock);
	mutex_init(&gf->ta_lock);
	platform_set_drvdata(pdev, gf);
	g_gf = gf;

	gf->core_clk = devm_clk_get(dev, "core_clk");
	if (IS_ERR(gf->core_clk))
		return dev_err_probe(dev, PTR_ERR(gf->core_clk), "core_clk\n");
	gf->iface_clk = devm_clk_get(dev, "iface_clk");
	if (IS_ERR(gf->iface_clk))
		return dev_err_probe(dev, PTR_ERR(gf->iface_clk), "iface_clk\n");

	gf->reset_gpio = devm_gpiod_get(dev, "reset", GPIOD_OUT_LOW);
	if (IS_ERR(gf->reset_gpio))
		return dev_err_probe(dev, PTR_ERR(gf->reset_gpio), "reset gpio\n");
	gf->irq_gpio = devm_gpiod_get(dev, "irq", GPIOD_IN);
	if (IS_ERR(gf->irq_gpio))
		return dev_err_probe(dev, PTR_ERR(gf->irq_gpio), "irq gpio\n");

	gf->vdd = devm_regulator_get_optional(dev, "vdd");
	if (IS_ERR(gf->vdd))
		gf->vdd = NULL;

	gf->irq = gpiod_to_irq(gf->irq_gpio);
	if (gf->irq < 0)
		return dev_err_probe(dev, gf->irq, "gpiod_to_irq\n");
	rc = devm_request_threaded_irq(dev, gf->irq, NULL, gf_irq,
				       IRQF_TRIGGER_RISING | IRQF_ONESHOT,
				       "goodix_fp", gf);
	if (rc)
		return dev_err_probe(dev, rc, "request_irq\n");
	disable_irq(gf->irq);
	gf->irq_enabled = false;

	gf->nl_sk = netlink_kernel_create(&init_net, GF_NETLINK_UNIT, &cfg);
	if (!gf->nl_sk)
		dev_warn(dev, "netlink create failed\n");

	gf->misc.minor = MISC_DYNAMIC_MINOR;
	gf->misc.name = "goodix_fp";
	gf->misc.fops = &gf_fops;
	rc = misc_register(&gf->misc);
	if (rc) {
		if (gf->nl_sk)
			netlink_kernel_release(gf->nl_sk);
		return dev_err_probe(dev, rc, "misc_register\n");
	}

	gf->gf_mem = qcom_scm_qseecom_tzmem_alloc(0x800, &gf->gf_mem_phys);
	gf->gf_pay = qcom_scm_qseecom_tzmem_alloc(0x800, &gf->gf_pay_phys);
	gf->gf_img = qcom_scm_qseecom_alloc_image(GF_IMG_SIZE, &gf->gf_img_dma);
	gf->km_mem = qcom_scm_qseecom_alloc_image(8192, &gf->km_dma);
	if (!gf->gf_mem || !gf->gf_pay || !gf->km_mem || !gf->gf_img)
		dev_warn(dev, "TA buffers unavailable (gf_img=%s)\n",
			 gf->gf_img ? "ok" : "FAILED");
	else
		dev_info(dev, "gf bufs cmd=%pa pay=%pa img_dma=%pad\n",
			 &gf->gf_mem_phys, &gf->gf_pay_phys, &gf->gf_img_dma);
	device_create_file(dev, &dev_attr_ginit);
	device_create_file(dev, &dev_attr_gcmd);
	device_create_file(dev, &dev_attr_gpay);
	device_create_file(dev, &dev_attr_gdump);
	device_create_file(dev, &dev_attr_capture);
	device_create_file(dev, &dev_attr_autocap);
	device_create_file(dev, &dev_attr_enroll);
	device_create_file(dev, &dev_attr_authenticate);
	device_create_file(dev, &dev_attr_trace);
	if (device_create_bin_file(dev, &bin_attr_frame))
		dev_warn(dev, "frame bin attr create failed\n");
	if (device_create_bin_file(dev, &bin_attr_snaps))
		dev_warn(dev, "snaps bin attr create failed\n");

	dev_info(dev, "goodix_fp ready: irq %d, core_clk %lu Hz\n",
		 gf->irq, clk_get_rate(gf->core_clk));
	return 0;
}

static void gf_remove(struct platform_device *pdev)
{
	struct gf_dev *gf = platform_get_drvdata(pdev);

	device_remove_file(&pdev->dev, &dev_attr_ginit);
	device_remove_file(&pdev->dev, &dev_attr_gcmd);
	device_remove_file(&pdev->dev, &dev_attr_gpay);
	device_remove_file(&pdev->dev, &dev_attr_gdump);
	device_remove_file(&pdev->dev, &dev_attr_capture);
	device_remove_file(&pdev->dev, &dev_attr_autocap);
	device_remove_file(&pdev->dev, &dev_attr_enroll);
	device_remove_file(&pdev->dev, &dev_attr_authenticate);
	device_remove_file(&pdev->dev, &dev_attr_trace);
	device_remove_bin_file(&pdev->dev, &bin_attr_frame);
	device_remove_bin_file(&pdev->dev, &bin_attr_snaps);
	misc_deregister(&gf->misc);
	gf_irq_set(gf, true);	/* balance so devm free_irq is clean */
	gf_clk_disable(gf);
	if (gf->power_on && gf->vdd)
		regulator_disable(gf->vdd);
	if (gf->gf_mem)
		qcom_scm_qseecom_tzmem_free(gf->gf_mem);
	if (gf->gf_pay)
		qcom_scm_qseecom_tzmem_free(gf->gf_pay);
	if (gf->gf_img)
		qcom_scm_qseecom_free_image(GF_IMG_SIZE, gf->gf_img, gf->gf_img_dma);
	if (gf->km_mem)
		qcom_scm_qseecom_free_image(8192, gf->km_mem, gf->km_dma);
	if (gf->nl_sk)
		netlink_kernel_release(gf->nl_sk);
	g_gf = NULL;
}

static const struct of_device_id gf_of_match[] = {
	{ .compatible = "goodix,fp-milanf" },
	{ }
};
MODULE_DEVICE_TABLE(of, gf_of_match);

static struct platform_driver gf_driver = {
	.probe = gf_probe,
	.remove = gf_remove,
	.driver = {
		.name = "goodix_fp",
		.of_match_table = gf_of_match,
	},
};
module_platform_driver(gf_driver);

MODULE_DESCRIPTION("Goodix Milan-F fingerprint char driver (mainline port)");
MODULE_LICENSE("GPL");
