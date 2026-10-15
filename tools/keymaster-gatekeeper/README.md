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

AI-assisted research; no vendor blobs included. Extract TAs from your own device.
