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

## Decisive update (2026-10-15): keymaster is GLOBALLY unprovisioned — it's the ROT, not just gatekeeper

A standard keymaster crypto op was tested from userspace: **`generate_key(0x508)`** (AES-128) →
**`-40`**, the same rejection as shared-HMAC. So it is **not** gatekeeper-specific — **every keymaster
operation that creates or derives key material fails** (generate `-40`, configure `-38`, shared-HMAC
`-40`, gatekeeper enroll `-30`); only the OEM FP-key *read* (`0x205`) works. That is the signature of
a keymaster whose **Root of Trust / boot-state was never set**. Per Android's own docs, the bootloader
supplies the ROT + OS version and `configure` checks it on the first boot call — which is exactly what
fails here.

There is **no keymaster *app* command** for the ROT in the vendor HALs (only the `KM_TAG_ROOT_OF_TRUST`
key tag); the ROT is delivered by a **bootloader SMC**. Therefore:

- **Halium cannot fix this.** It runs in userspace after boot; the ROT SMC is one-shot and happens
  before Linux. Running `keystored`/`gatekeeperd` under Halium would still hit the unprovisioned TA.
- **lk2nd (or the stock ABL path) is the only route.** The fix is to make the boot chain set the
  keymaster Root-of-Trust / boot-state for the kernel it boots, before handing off.

### Concrete lk2nd investigation
1. Find how the stock **ABL/XBL** sets the keymaster ROT/boot-state on this SoC (the Qualcomm
   `scm`/`qsee` set-boot-state call, or the SMEM/IMEM region keymaster reads). lk2nd is loaded *by*
   ABL as the boot image, so determine whether ABL sets the ROT for lk2nd and whether that state is
   usable by keymaster from Linux, or whether lk2nd must (re-)issue it.
2. If lk2nd must issue it: add the set-boot-state SMC to lk2nd before it boots Linux, with the
   verified-boot fields (state, device-locked, VB key hash, boot hash). **Caveat:** the ROT set is
   typically **one-shot, locked after the first call** — if ABL already set it (even to an
   unlocked/orange value) the call is closed, and crypto failing anyway would mean the problem is a
   *value* keymaster rejects, not a missing call. Establish which case this is first.
3. This is **uncharted for sdm845** (a web search found no solved case) — it is a genuine
   bootloader/TrustZone project with uncertain feasibility, not a config tweak.

## The route — investigation order

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
