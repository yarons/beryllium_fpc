# keymaster / gatekeeper probes (over the /dev/qseecom shim)

Run on-device as root with `qseecom_shim.ko` loaded. They talk to the resident
`keymaster64` (app_id 1) and the Goodix `gfber` TA. See `../../GATEKEEPER-BOOTLOADER-ROUTE.md`
for the command IDs, errors, and the open questions these probe.

- `gkmint.py`   — gatekeeper ENROLL(0x1001)/VERIFY(0x1002) + HAT mint attempt
- `gksweep.py`  — sweep uid/pw on GK_ENROLL (shows -30 is input-independent)
- `gkconfig.py` — keymaster configure(0x116) param-set
- `gkrot.py`    — KEYMASTER_SET_ROT(0x201), lk2nd boot_verifier flow, then crypto retry
- `gkhmac.py`   — GET_HMAC_SHARING_PARAMS(0x706) + COMPUTE_SHARED_HMAC(0x707)
- `gkgen2.py`   — generate_key via 0x508 (new) vs 0x108 (old) + GET_VERSION/device-state

2026-10-15 session 2 (exact ABI recovered — see the doc's "session 2" section):
- `gkgen5.py`   — generate_key with the **correct** RE'd wire format + key-spec sweep (reaches semantic validation)
- `gkcfg.py`    — configure(0x116) os_version/patchlevel, then generate (tests the "not configured" theory)
- `gkdisc.py`   — proves 0x108's `-8` is **frozen vs content** (global gate, not block-mode validation)
- `gksweep2.py` — cmd-id sweep; found ROT `0x20c/0x20d -> -1 ALREADY_SET` and the parse/no-parse boundary
- `gkhmac2.py`  — 0x706 -> 0x707 early-boot HMAC handshake, then re-test generate
- `gkver.py`    — GET_VERSION dump (message v3), resp placement (far/contiguous) + SEND_MODFD transport tests

AI-assisted research; no vendor blobs included. Extract TAs from your own device.
