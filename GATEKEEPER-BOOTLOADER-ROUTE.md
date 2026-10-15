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
