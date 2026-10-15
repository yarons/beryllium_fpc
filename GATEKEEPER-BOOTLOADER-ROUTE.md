# The bootloader route to a working fingerprint unlock (Path A)

> For anyone (pmOS / lk2nd / sdm845 folks) who wants to take the Pocophone F1 Goodix
> fingerprint from "reader works, no unlock" to a real unlock. Context: [`UNLOCK.md`](UNLOCK.md),
> deep log in [`re/notes/protocol.md`](re/notes/protocol.md). AI-assisted; see [`NOTICE`](NOTICE).

## The problem, precisely

The reader works end-to-end **up to frame capture** (keymaster FP key, `gfber` init, firmware
version, a real `op39` frame on touch). What is blocked is **enroll** — and therefore any match:

- The Goodix TA (`gfber`) `ENROLL` (grp1/1007) requires a **gatekeeper HAT** (hardware auth token)
  and genuinely verifies its HMAC (confirmed: fixing the challenge moves the error `1056`→`1057`,
  the HMAC check).
- The untrusted enroll (grp3/1060) is one-shot and cannot accumulate a template.
- Software image matching is **not viable** either: the raw `op39` frames can't discriminate
  fingers (tested — same-finger pairs score no higher than different-finger pairs), and the TA
  keeps its preprocessed image internal.

So a working unlock needs a **real gatekeeper HAT**, and the gatekeeper **refuses to produce one**.

## What we reverse-engineered about the gatekeeper

On Qualcomm there is **no separate gatekeeper trustlet** — gatekeeper is implemented **inside the
keymaster TA** (resident, `app_id = 1`). The vendor HAL
`android.hardware.gatekeeper@1.0-impl-qti.so` sends commands to keymaster via
`keymasterutils::KeymasterUtils::send_cmd` (a plain `QSEECom_send_cmd`). The commands:

| Command | ID (TEE / StrongBox) | Request shape |
|---|---|---|
| `GK_ENROLL` | `0x1001` / `0x1501` | `[0]=cmd [4]=uid [8..]=3×{off,len}` for {curHandle, curPw, desiredPw} |
| `GK_VERIFY` | `0x1002` / `0x1502` | `[0]=cmd [4]=uid [8]=challenge(u64) [10..]=2×{off,len}` for {handle, pw} |
| keymaster `configure` | `0x116` | `[0]=cmd [4]=params_off [8]=count` + params, each 12B `{tag,u32,pad}` |

The keymaster TA **dispatches** these (the SMC succeeds, the TA runs) but **`GK_ENROLL` returns
`-30` = `KM_ERROR_VERIFICATION_FAILED`** — **identical across every uid and password**, i.e. it
fails *before* reading the request. A first-time enroll has nothing to verify, so this is the
keymaster/gatekeeper **internal key/state check failing**, not a bad request.

### Ruled out (so you don't repeat it)

- **Request format** — confirmed correct by disassembling `GatekeeperHalDevice::enroll/verify`.
- **uid / password** — swept uid `{0,1,1000,10000,100000,0xdeadbeef}` × pw-len `{4,16}`; all `-30`.
- **keymaster `configure(0x116)`** — serialization RE'd and sent (params `KM_TAG_OS_VERSION`
  `0x300002C1`, `KM_TAG_OS_PATCHLEVEL` `0x300002C2`); it returns `-38` for any value and does **not**
  change the enroll `-30`.

Note keymaster is **not** dead in general: the Goodix FP-key op (`0x205`) works once the FPC TA
`fpcber` is resident. So this is **gatekeeper-specific**: the gatekeeper key path is uninitialized.

## The hypothesis: missing boot-time provisioning

On Android the boot chain initializes keymaster/gatekeeper; on postmarketOS it does not:

1. **XBL/ABL** set the keymaster **Root of Trust** (verified-boot key hash + lock state) via a
   one-shot SMC early in boot. (On the Poco F1, Qualcomm's XBL/ABL still run before lk2nd, so the
   ROT *may* already be set — worth verifying, not assuming.)
2. **keystored** calls keymaster `configure(os_version, patchlevel)` and `addRngEntropy` at boot.
3. **gatekeeperd / vold** drive gatekeeper for lockscreen auth.

On pmOS, lk2nd chainloads Linux and none of the keystore/vold/gatekeeperd initialization happens.
The input-independent `VERIFICATION_FAILED` is consistent with the **gatekeeper HMAC key never
being derived/provisioned** because that boot-time setup is absent.

## 2026-10-15 deep dive — lk2nd/keymaster commands, the real errors, and the OPEN gatekeeper puzzle

**This is the current frontier. It is a well-characterized OPEN problem — a good target for extra eyes
(other LLMs / GitHub Copilot / pmOS + sdm845 folks). Everything below is reproducible from this repo's
`/dev/qseecom` shim + driver; the probe scripts are in the project scratchpad (`gkmint.py`, `gkgen*.py`,
`gkrot.py`, `gkhmac.py`).**

### The keymaster command space on this device (keymaster64, app_id 1)
From lk2nd's `include/km_main.h` (bootloader keymaster) + the vendor HALs:
`KEYMASTER_CMD_ID=0x100`, `KEYMASTER_UTILS_CMD_ID=0x200`.

| Command | ID | Source |
|---|---|---|
| GET_VERSION | `0x200` | lk2nd km_main.h — **works, returns 0** |
| SET_ROT | `0x201` | lk2nd `boot_verifier.c: send_rot_command` |
| READ_LK_DEVICE_STATE | `0x202` | lk2nd — **works, returns 0** |
| SET_BOOT_STATE | `0x208` | lk2nd `boot_verify_send_boot_state` |
| ADD_RNG_ENTROPY | `0x107` | lk2nd km_main.h |
| GENERATE_KEY (old) | `0x108` | lk2nd km_main.h |
| configure | `0x116` | vendor `KeymasterHalDevice::configure` |
| generate_key (new) | `0x508` | vendor KM3 HAL |
| GET_HMAC_SHARING_PARAMS / COMPUTE_SHARED_HMAC | `0x706` / `0x707` | vendor KM4 HAL |
| OEM FP-key get (Goodix) | `0x205` | `libgf_ca get_key_from_keymaster` — **works** |
| gatekeeper ENROLL / VERIFY | `0x1001` / `0x1002` | vendor gatekeeper@1.0 HAL |

### Error codes (standard `keymaster_error_t`, confirmed `KM_ERROR_INVALID_TAG = -40` in km_main.h)
`-1` ROOT_OF_TRUST_ALREADY_SET · `-8` INCOMPATIBLE_BLOCK_MODE · `-15` INVALID_USER_ID ·
`-30` VERIFICATION_FAILED · `-38` INVALID_ARGUMENT · `-40` INVALID_TAG.

### What was observed (from the shim, keymaster app_id 1)
- `GET_VERSION(0x200)` → **0**, `READ_LK_DEVICE_STATE(0x202)` → **0**. So keymaster **responds** and the
  no-arg util path works. (So the earlier "keymaster is globally unprovisioned" claim is **retracted** —
  it is not clearly unprovisioned.)
- Param-based commands fail with *param-shaped* errors regardless of values: `generate_key 0x508` →
  `-40 INVALID_TAG`; `generate_key 0x108` → `-8` for AES-CBC, AES-ECB, **and HMAC** (HMAC has no block
  mode, so `-8` here is not literally "block mode" — it points at **our param serialization being
  wrong**, not the key config). `configure 0x116` → `-38 INVALID_ARGUMENT`.
  **Open #1: what is the exact keymaster param-set wire format this TA expects?** Our current guess is
  12-byte entries `{tag(u32), value(u32), pad(u32)}` after a `[cmd, params_off, count]` header (RE'd
  from `KeymasterHalDevice::params_serialize`). Getting one `generate_key` to return a key blob would
  prove crypto works and isolate the gatekeeper issue.
- `SET_ROT(0x201)` from userspace (lk2nd's exact request: `{cmd_id, rot_offset=12, rot_size=32}` +
  `SHA256(is_unlocked_byte)` for the ORANGE/unlocked path) → `-15 INVALID_USER_ID` (not `-1`
  ALREADY_SET). `send_rot_command` **is** called in the stock boot path (`app/aboot/aboot.c:2019`).
  **Open #2: is the ROT already set by ABL (so the gatekeeper issue is elsewhere), or does
  lk2nd-beryllium skip it?** `-15` (not `-1`) is ambiguous — could be a format/user mismatch or the
  newer TA rejecting a direct SET_ROT.
- **The core wall: gatekeeper `ENROLL(0x1001)` → `-30 VERIFICATION_FAILED`, request format verified
  against `GatekeeperHalDevice::enroll` disasm, identical across every uid/password.** For a first
  enroll (null current password) nothing should be verified.
  **Open #3: why does a first gatekeeper enroll fail verification?** Candidates: the gatekeeper↔keymaster
  auth-token shared key is not established (the KM4 `COMPUTE_SHARED_HMAC 0x707` returns `-40` on this
  KM3-era TA); or `0x1001` is the wrong gatekeeper command id for this TA generation; or `gatekeeperd`
  does a boot-time init we have not replicated.

### Does Halium vs lk2nd still apply?
Undetermined now, because keymaster is **not** cleanly "unprovisioned." If Open #2 shows the ROT is set,
the fix is likely a **gatekeeper-level init** (reachable by running `gatekeeperd`/`keystore` — i.e. a
Halium or a replicated command sequence), not a bootloader change. If the ROT is genuinely unset and
locked, it is lk2nd. **Resolving Open #1 (param format → a working `generate_key`) and Open #2 (ROT
state) decides which.**

## 2026-10-15 session 2 — exact ABI recovered; Open #1 & #2 resolved; the wall re-characterized

**Big update: the earlier "wrong param format" / "ROT maybe unset" branches are now closed by
reverse-engineering the vendor HAL (`libqtikeymaster4.so` / the keymaster3 HAL) and by on-device
probing. The wall is not format, not transport, and not the bootloader ROT.** All results below are
reproducible from this repo's shim; scripts: `gkgen5.py`, `gkcfg.py`, `gkdisc.py`, `gksweep2.py`,
`gkhmac2.py`, `gkver.py` (project scratchpad).

### Open #1 — RESOLVED: exact keymaster `generate_key` / `configure` wire format
RE'd from `KeymasterHalDevice::generate_key_common`, `configure`, and `params_serialize` (disasm):

```
request:  [u32 cmd][u32 params_offset = 0x0c][u32 param_COUNT]  then COUNT x 12-byte records
record (12B): [u32 tag][value]   value width by tag type nibble (tag>>28):
  1/2/3/4 ENUM,ENUM_REP,UINT,UINT_REP -> u32 (+pad to 12)
  5/6/0xA ULONG,DATE,ULONG_REP         -> u64
  7       BOOL                          -> 1 byte
  8/9     BIGNUM,BYTES                  -> [u32 offset_from_buf_start][u32 len]; data in a
                                           separate indirect region after the records
response: [i32 status][...][u32 key_blob_offset @0x08][u32 key_blob_len @0x0c]
```
This is **not** the AOSP `AuthorizationSet::Serialize` framing (no `indirect_size/count/elems_bytes`
prefix) — QTI uses a bare 12-byte-record array with the count in the header. Our original guess was
structurally correct; `generate_key` reaches **semantic** validation, so the format is **not** the
blocker.

- **`generate_key (new) = 0x508` is the StrongBox/SPU command** (selected only when the HAL's
  `security_level == 2`). SDM845 beryllium has no SPU, so `0x508` → `-40` is meaningless noise. The
  real generate on this TA is **`0x108`** (confirmed identical selection logic in the KM3 and KM4 HALs).

### Open #2 — RESOLVED: the Root of Trust *is* set by the bootloader
Probing the ROT-set command range: `0x20c` / `0x20d` → **`-1 ROOT_OF_TRUST_ALREADY_SET`**. So ABL/XBL
provisions the ROT before Linux; lk2nd-beryllium does not need to (and `SET_ROT 0x201` → `-15` is just
the TA refusing a second/foreign set). **The ROT is not the gap.**

### The wall, re-characterized: every privileged keymaster op is refused by a canned, input-independent error — in-TZ
With the exact format, and varying every input, the response-buffer placement (far vs contiguous) and
the transport (plain `SEND_CMD` vs `SEND_MODFD_CMD`):

| Command | ID | Result | Moves with input? |
|---|---|---|---|
| get_version | `0x200` | **0** (reports keymaster **message v3**) | n/a (works) |
| read_device_state | `0x202/0x203` | **0** | n/a (works) |
| ROT query | `0x20c/0x20d` | **-1 ROT_ALREADY_SET** | n/a |
| generate_key | `0x108` | **-8**, frozen (even **empty** params; AES/RSA/EC/HMAC all identical) | **no** |
| configure | `0x116` | **-38**, frozen (every os_version/patchlevel tried) | **no** |
| get_hmac_sharing_params | `0x706` | **-40**, frozen (no-arg command) | **no** |
| compute_shared_hmac | `0x707` | **-40**, frozen | **no** |
| gatekeeper enroll | `0x1001` | **-30**, frozen | **no** |

Crucial: these commands **complete inside the TA** — the shim's `qs_send` returns `0` (SMC
`r.result == 0`) and the keymaster error is delivered *in-band* in the response buffer. No QSEE
**listener** callback is triggered (a pending listener would surface as `r.result != 0` → `-EIO`,
which never happens). So the shim's missing listener services are **not** the cause for these
failures, and **transport/format/placement are all ruled out.** The refusal is a pure **internal TA
precondition/state check**.

### What this means
The TA answers read/utility commands but refuses *every* key-creating / config / HMAC-sharing /
gatekeeper-enroll command with a fixed, input-independent error, entirely in secure world. That is the
signature of a **secure-world bring-up step that Android's `keystore2` / `gatekeeperd` / early-boot
stack performs once per boot and that pmOS never does** — and the natural entry point to reproduce it
(`get_hmac_sharing_parameters 0x706`) is itself refused from the plain userspace path. Whether that
bring-up is reachable from a privileged Linux context or only from the bootloader/TZ is **the**
remaining question; the evidence (even the no-arg `0x706` is refused; nothing input-dependent ever
parses) leans toward a boot-context/privilege gate rather than a single sendable command.

### Sharpest next experiments (for extra eyes)
1. **Instrument the shim** (`qs_send`): log `r.result` and detect `QSEOS_RESULT_INCOMPLETE /
   BLOCKED_ON_LISTENER` on `0x108/0x116/0x706/0x1001`, to *prove* (not infer) no listener is wanted.
2. **Capture a stock-boot keymaster trace** (what `keystore2`/`gatekeeperd` send at boot on stock
   MIUI/LOS) and replay it verbatim — especially whatever precedes the first `generate_key`.
3. **`configure 0x116` with the full boot-param tag set** (VERIFIED_BOOT_STATE, BOOT_PATCHLEVEL,
   VBMETA_DIGEST), not just os_version/patchlevel — `-38` may mean "missing required boot params".
4. If 1–3 show the gate needs TZ/boot context → it is an **lk2nd / early-init** step after all.
5. Pragmatic alternative for a *working* (if not PIN-bound) unlock: the **libfprint image path**
   (software match on `op39` frames) — independent of this entire keymaster wall.

## 2026-10-15 session 3 — ROOT CAUSE PROVEN: the missing QSEE secure-storage / RPMB listener

**The gate is no longer a hypothesis.** Dumped the keymaster TA from the `keymaster_a` partition (authorized
RE of an owned device; the TA binary is **not** redistributed) and disassembled it (capstone). The wall is
the **absent QSEE secure-storage/RPMB listener service**, and it is a **Linux-side** problem — *not* the
bootloader. This supersedes the "boot-context/lk2nd, mechanism unknown" framing above and the
bootloader-centric "## The route" section below.

### The TA bails during init when secure storage is unavailable
Keymaster TA init path (reconstructed from disasm + its own diagnostic strings):
`KEYMASTER Init → is_secure_boot_enabled → rpmb_init → qsee_stor_device_init`.
- `rpmb_init` failure → **KM_ERROR_KEYMASTER_NOT_CONFIGURED (-64)**.
- on a secure-boot device, `qsee_stor_device_init` failure → logs *"secboot device && rpmb error, BAILING
  OUT"*, returns **-10001**, and sets a global keymaster-failed flag.
beryllium's TZ secure-boot fuse is blown independently of the bootloader unlock → it **is** a secboot
device → when storage is unavailable the TA bails at init and marks keymaster not-ready.

### Every refused command is storage-backed; every working command is not
- **Work** (no secure storage): `GET_VERSION 0x200`, device-state `0x202`, ROT-query `0x20c`
  (ALREADY_SET), OEM Goodix FP-key `0x205`.
- **Refused** (need secure storage / RPMB): `generate 0x108 (-8)`, `configure 0x116 (-38)`,
  shared-hmac `0x706/0x707 (-40)`, **gatekeeper enroll `0x1001 (-30)`**.
Gatekeeper enroll is RPMB-backed *directly*: its handler calls `gk_get_rpmb_data` / `ThrottleRequest` /
RPMB reboot-detection (the TA's own strings) — without RPMB it fails, hence the input-independent `-30`.
Because the TA already bailed at init, these refuse **without even attempting a listener callback** — the
kernel log shows every send returning `resp_type = QSEOS_APP_ID (0xee01)`, never `QSEOS_LISTENER_ID
(0xee02)`.

### Why pmOS can't satisfy it (and Android does)
Android's **qseecomd** registers the QSEE listener services (an **RPMB** relay and a **Secure File System**
service) and then sets `vendor.sys.listeners.registered=true`. The vendor HAL's `gk_initialize` literally
polls that property before it will use keymaster. On pmOS none of that exists:
- the fork's `qcom_scm` exports only `qcom_scm_qseecom_app_{get_id,send,send_phys,load_image,shutdown,
  region_notify}` (the set needed for `uefisecapp`) — **no listener-callback framework** (no
  register-listener, no `QSEOS_RESULT_INCOMPLETE`/`QSEOS_LISTENER_ID` continuation loop). The
  `/dev/qseecom` shim stubs `RECEIVE_REQ`/`SEND_RESP_REQ` accordingly.
- no userspace listener daemon.

### The fix (entirely Linux-side; ROT already set, no lk2nd change)
1. **Kernel** — add QSEE listener support to `qcom_scm`: the register-listener call and the
   incomplete-command continuation loop (when the TA returns `QSEOS_LISTENER_ID`, service the request
   and resume via `LISTENER_RESPONSE`). **Started:** [`kernel-patches/0001-qcom_scm-qseecom-listener.patch`](kernel-patches/)
   adds the in-kernel listener framework (`qcom_scm_qseecom_listener_register()` + the service loop),
   ported from samcday's QSEECOM TEE work. A service backend (below) fills a listener and registers it.
2. **Userspace** — a small qseecomd-equivalent implementing the two services the TA needs at init:
   - **Secure File System (SFS)** — back it with the `storsec_a`/`storsec_b` partitions (present on this
     device: `sde10`/`sde11`).
   - **RPMB relay** — relay the TA's RPMB frames to the UFS RPMB well-known LUN. **Prerequisite:** this is
     a **UFS** device (no eMMC `/dev/*rpmb`); the UFS RPMB LUN is **not currently exposed** to Linux, so a
     UFS-RPMB chardev / scsi-generic path must be enabled first. The listener is only a frame **relay** —
     the RPMB authentication key lives inside the TA (factory-provisioned), so the daemon needs no secret.
3. Then keymaster init succeeds → `generate`/`configure`/`GK_ENROLL(0x1001)` work → mint a HAT →
   trusted `gfber ENROLL(1007)` → `AUTHENTICATE(1010)` → libfprint/fprintd/pam_fprintd → Phosh.

### Open specifics for implementers
- Exact QSEE **listener service IDs** for SFS and RPMB on this TZ build (recoverable from qseecomd, or by
  logging the shim's first `RECEIVE_REQ` once callback support exists).
- UFS RPMB LUN exposure on mainline sdm845.
- This is sizeable (kernel + daemon + UFS-RPMB), but it is ordinary Linux driver/daemon work — the
  reverse-engineering uncertainty is now gone.

## The route — investigation order (if it is the bootloader after all)

1. **Is the Root of Trust actually set on this boot?** Query keymaster for something ROT-dependent
   (an attestation / `GET_HW_INFO` / a key-gen that binds ROT) and compare pmOS vs a stock-boot
   capture. If the ROT is missing, that is the gap.
2. **Can the missing step be done from Linux userspace?** This is the best case — no bootloader
   change. We RE'd the provisioning commands and **tried the most promising ones over the shim; none
   open the gatekeeper:**
   - keymaster `configure(0x116)` (os-version/patchlevel) → `-38`, does not change the enroll.
   - **`KM_GET_HMAC_SHARING_PARAMETERS (0x706)` + `KM_COMPUTE_SHARED_HMAC (0x707)`** — the
     ISharedSecret protocol that establishes the gatekeeper/keymaster shared HMAC key — → **`0x706`
     returns `-40`**. The resident `keymaster64` TA does **not** implement shared-HMAC (consistent
     with a keymaster **3.0** TA; ISharedSecret is a 4.0 concept, even though a `libqtikeymaster4.so`
     ships on the device). So the KM4 shared-secret route does not apply to this TA.
   Remaining userspace candidates (unexplored): a KM3-era auth-token-key / gatekeeper-key init
   (check `android.hardware.keymaster@3.0-impl-qti.so` + `libkeymasterdeviceutils.so` for a
   `get_auth_token_key`-style command), or `libkeymasterprovision.so`'s `KeyMasterProvisionInit` /
   `ProvisionDeviceId` / keybox-install path (device-ID/attestation provisioning — may or may not
   touch the gatekeeper key). The resident TA dispatches these commands but rejects them
   (`enroll -30`, `configure -38`, `shared-hmac -40`), which points to **state the Android
   keystore/gatekeeperd/bootloader stack sets up at boot** rather than a single sendable command.
3. **If it must happen in the bootloader**, add it to **lk2nd**: send the keymaster ROT / run the
   provisioning SMC before handing off to Linux. ROT-set is typically a one-shot locked after first
   call, so if XBL already locked it with a different value, this may be impossible without changing
   the earlier chain — establish that first.
4. **Then** mint the HAT: `GK_ENROLL(0x1001)` with a PIN → handle, `GK_VERIFY(0x1002)` with the
   `gfber` pre-enroll challenge → HAT, feed to `gfber` `ENROLL(1007)` → continuous enroll →
   `AUTHENTICATE(1010)` → libfprint/fprintd/pam_fprintd → Phosh. **No Phosh changes needed.**

## Pointers

- Vendor libs that hold the provisioning/keymaster logic (extract from your own device; **not**
  redistributed here): `libqtikeymaster4.so`, `libkeymasterprovision.so`,
  `libkeymasterdeviceutils.so`, `android.hardware.gatekeeper@1.0-impl-qti.so`.
- lk2nd (the pmOS bootloader for sdm845) is where a boot-time SMC would go.
- The `/dev/qseecom` shim + driver in this repo let you talk to keymaster (`app_id 1`) and `gfber`
  from Linux to prototype any userspace provisioning before touching the bootloader.

If you crack step 1/2, the rest is already mapped here. The most valuable next result is simply
**knowing whether the ROT/provisioning gap can be closed from userspace or only from lk2nd.**
