// SPDX-License-Identifier: GPL-2.0
/*
 * Test-only: ask QSEE (TrustZone) for the app IDs of a few trusted apps by
 * name, to see whether the QSEECOM path answers on this firmware.
 */
#include <linux/firmware/qcom/qcom_scm.h>
#include <linux/module.h>

static char *apps[8] = { "fpcber", "gfber", "fingerpr", "keymaster",
			 "keymaster64", "cmnlib64", "widevine", "qcom.tz.uefisecapp" };
static int napps = 8;
module_param_array(apps, charp, &napps, 0444);

static int __init qseecom_probe_init(void)
{
	int i, ret;
	u32 id;

	for (i = 0; i < napps; i++) {
		id = 0;
		ret = qcom_scm_qseecom_app_get_id(apps[i], &id);
		pr_info("qseecom_probe: %-20s ret=%d id=%u\n", apps[i], ret, id);
	}
	return 0;
}

static void __exit qseecom_probe_exit(void) { }

module_init(qseecom_probe_init);
module_exit(qseecom_probe_exit);
MODULE_DESCRIPTION("QSEECOM app lookup probe (test only)");
MODULE_LICENSE("GPL");
