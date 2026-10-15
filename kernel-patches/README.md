# Kernel patches — Path A enabler

Path A (a real, PIN-bound fingerprint unlock via the keymaster/gatekeeper TA) is blocked because the
keymaster TA **bails at init without secure storage** and gatekeeper enroll is RPMB-backed — see
[`../GATEKEEPER-BOOTLOADER-ROUTE.md`](../GATEKEEPER-BOOTLOADER-ROUTE.md) "session 3". The TA reaches the
normal world through **QSEE listeners**, which the sdm845 mainline `qcom_scm` does not implement (it only
has app lookup/send/version and explicitly `WARN_ON`s incomplete/blocked results). This directory holds
the kernel work to close that gap.

## `0001-qcom_scm-qseecom-listener.patch` — QSEE listener framework in `qcom_scm`

Adds the listener half of the QSEECOM SCM interface:

- `enum` additions: `QSEECOM_TZ_SVC_LISTENER = 2`, cmds `LISTENER_REGISTER/DEREGISTER/RESPONSE = 1/2/3`.
- `qcom_scm_qseecom_service_listeners()` — the loop that runs inside `qcom_scm_qseecom_call()` under the
  call lock: while a send returns `QSEECOM_RESULT_INCOMPLETE` naming a listener id, it finds the
  registered listener, calls its `->service()`, and answers with `LISTENER_RESPONSE` to resume the app.
  Replaces the two `WARN_ON`s. Caps runaway apps at 256 rounds; fails unknown ids rather than parking TZ.
- `qcom_scm_qseecom_listener_register()` / `_unregister()` (EXPORT_SYMBOL_GPL) + the
  `struct qcom_scm_qseecom_listener { id; sb; sb_len; service; node }` and status enum in the header.

**This is the enabler only.** It lets a kernel module *offer* a listener; it does not implement the
storage services the keymaster TA actually asks for. Those are the next component (below).

### Provenance / license
GPL-2.0-only (same as the kernel). The listener code is ported, near-verbatim, from samcday's QSEECOM
TEE work — [github.com/samcday/linux PR #14](https://github.com/samcday/linux/pull/14), commit
"firmware: qcom: scm: add QSEECom app loading and listener services" (Copyright (C) 2026 Dawid Wróbel).
A sibling implementation exists at
[github.com/yzddmr6/linux-sm8450-liuqin PR #7](https://github.com/yzddmr6/linux-sm8450-liuqin/pull/7).
The patch is diffed against sdm845-mainline `qcom_scm.c` at `sdm845/7.1-dev`.

### Apply + build + test
The patch targets `drivers/firmware/qcom/qcom_scm.c` + `include/linux/firmware/qcom/qcom_scm.h`.

```sh
cd /work/fork            # the sdm845 fork tree used by build-env
git apply --3way ../fingerprint/kernel-patches/0001-qcom_scm-qseecom-listener.patch
# If the one-line hook in qcom_scm_qseecom_call() fuzzes (this tree carries local
# "qseecom raw:" logging there), apply it by hand: after
#   status = __qcom_scm_qseecom_call(desc, res);
# add:
#   if (!status) status = qcom_scm_qseecom_service_listeners(res);
# and delete the two WARN_ON(res->result == QSEECOM_RESULT_{INCOMPLETE,BLOCKED_ON_LISTENER}) lines.
```

`qcom_scm` is built into the image (not a module), so this needs a kernel rebuild (`build-env/build.sh`)
and a RAM-boot to test (`fastboot boot` the test image — do **not** flash first). Risk: a RAM-boot can
drop the device off USB and need a manual power-cycle; never do it unattended.

Smoke test (no fingerprint needed): from a kernel module (or extend `qseecom_shim`) register a dummy
listener with a tzmem `sb` and a `service` that returns `QSEECOM_LISTENER_SUCCESS`, then re-run the
keymaster init path. Success signal: the keymaster TA's init stops bailing — `generate_key(0x108)` moves
off its frozen `-8`, and the kernel log shows sends returning `resp_type = QSEOS_LISTENER_ID (0xee02)`
being serviced instead of the TA refusing early.

## Next component (not here yet): the storage listener services
The keymaster TA needs two real listeners at init (`rpmb_init`, `qsee_stor_device_init`):
- **Secure File System (SFS)** — back it with `storsec_a`/`storsec_b` (present: `sde10`/`sde11`).
- **RPMB relay** — relay the TA's RPMB frames to the UFS RPMB well-known LUN. This device is **UFS**
  (no eMMC `/dev/*rpmb`); the UFS RPMB LUN is not exposed to Linux yet — a prerequisite.

Open specifics: the exact SFS/RPMB **listener service IDs** and request formats this TZ build uses
(recoverable from a downstream `qseecomd`, or by logging the first `->service()` request once this patch
is in). The listener is a frame **relay** — the RPMB auth key lives in the TA, so no secret is needed.
