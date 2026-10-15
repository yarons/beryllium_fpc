# Fingerprint unlock status — and the gatekeeper wall

> Companion to [`re/notes/protocol.md`](re/notes/protocol.md). This explains **why there is no
> working unlock yet**, exactly where the wall is, and the two realistic paths past it.
> AI-assisted work; see [`NOTICE`](NOTICE).

## TL;DR

The Goodix Milan-F reader is **fully alive up to frame capture** on mainline/pmOS. What is *not*
working is **enroll + match (the actual unlock)** — and the blocker is **not** the kernel, not
libfprint, and **not** Phosh. It is the **TrustZone gatekeeper refusing to mint a hardware auth
token (HAT)** on postmarketOS.

## What works

Power/clock/reset + IRQ (kernel driver) → keymaster FP key (needs the FPC trustlet `fpcber`
resident, see protocol.md Finding E) → `gfber` init (DETECT/INIT/INIT_FINISHED) → **sensor firmware
version read over SPI** → **a real image frame on finger touch** (`op39`, 88×108). End to end, from
scratch, no vendor HAL.

## Why there is no unlock — the enroll problem

The Goodix TA (`gfber`) offers two enroll paths:

| Path | Command | HAT needed? | Problem |
|------|---------|-------------|---------|
| Trusted | `ENROLL` grp1/1007 | **Yes** (gatekeeper HAT) | TA verifies the HAT; we can't mint one (below) |
| Untrusted | `TEST_UNTRUSTED_ENROLL` grp3/1060 | No | **One-shot** — one frame per `ginit`, no continuous accumulation |

- The **untrusted** path produces exactly one acquire per init and does not re-arm detect, so it can't
  accumulate a multi-frame template (protocol.md Finding Z).
- The **trusted** path is continuous (the TA holds finger-detect across touches) but requires a
  gatekeeper **HAT**, and the TA genuinely verifies it: feeding a correct challenge but a zero HMAC
  moves the error `1056` (challenge) → `1057` (HMAC) — the HMAC *is* checked (Finding Y).
- `AUTHENTICATE` (grp1/1010) needs **no** HAT, but needs a template that only enroll can create.

## The gatekeeper wall

On Qualcomm there is **no separate gatekeeper trustlet** — gatekeeper is implemented **inside the
keymaster TA** (resident, `app_id=1`). The vendor `android.hardware.gatekeeper@1.0-impl-qti.so` just
sends commands to keymaster. We reverse-engineered them:

- `GK_ENROLL = 0x1001`, `GK_VERIFY = 0x1002` (TEE; `0x1501`/`0x1502` for StrongBox)
- keymaster `configure = 0x116` (os-version / os-patchlevel)
- request layout and the keymaster param serialization — all RE'd (protocol.md Findings AA/BB)

The keymaster TA **dispatches** these commands (the SMC succeeds, the TA runs) but **refuses to
enroll**: `GK_ENROLL` returns `-30` (`KM_ERROR_VERIFICATION_FAILED`) — **identical across every uid
and password**, so it fails *before* reading the request. `configure` was also tried (with the exact
param serialization) and does not clear it. On Qualcomm the gatekeeper handle is
`HMAC(password, salt, hw_key)` with a hardware-derived key, so a first enroll *should* just work; the
input-independent `VERIFICATION_FAILED` means the keymaster/gatekeeper **state is not initialized on
pmOS** — the setup Android's keystore/vold perform at boot never happens, and it can't be triggered
from Linux userspace.

**So: a working unlock cannot be reached purely from Linux userspace through the vendor TA path.**

## Two realistic paths forward

**A. Provision the gatekeeper at the bootloader level (lk2nd / pmOS).**
(Full investigation plan: [`GATEKEEPER-BOOTLOADER-ROUTE.md`](GATEKEEPER-BOOTLOADER-ROUTE.md).)
Make lk2nd (or an early pmOS boot step) perform the keymaster/gatekeeper initialization Android does
at boot, so `GK_ENROLL` succeeds → mint a HAT → trusted `gfber` ENROLL(1007) → template →
`AUTHENTICATE`(1010). "Correct" and PIN-bound, but it's bootloader/TZ work with an uncertain exact
mechanism.

**B. Software image matching — bypass TrustZone enroll/verify entirely.**
We can already capture frames. Do the matching **in software**:
`libfprint` **image-type driver** (capture `op39` frames) → NBIS minutiae + bozorth3 matching in
libfprint → enroll/verify in `fprintd` → `pam_fprintd` → Phosh. **No gatekeeper, no HAT, no Phosh
patch.** The open question is **image quality**: raw `op39` frames are fixed-pattern-noise-dominated
and need a calibration base (a finger-off reference to subtract, or the TA's processed-acquire path)
to expose NBIS-usable ridges. If the sensor can yield clean ridge images, this is the practical road
to a working unlock.

## What is NOT the problem

Phosh, PAM, libfprint, fprintd, and the kernel driver are all fine. Phosh needs **no modification** —
it unlocks via `pam_fprintd` like any GNOME system. The single blocker is the sensor being unable to
produce an enrolled template on pmOS, for the gatekeeper reason above.
