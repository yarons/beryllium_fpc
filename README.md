# Goodix Milan-F fingerprint on the Pocophone F1 (mainline / postmarketOS)

Reverse-engineering notes, a mainline kernel driver, and a `/dev/qseecom` shim for
the **Goodix Milan-F** in-display-adjacent capacitive fingerprint sensor on the
**Xiaomi Pocophone F1** (`beryllium`, SDM845), running a mainline-based kernel
(postmarketOS, 7.2.9-sdm845).

> **Status: research / work-in-progress. There is NO working unlock yet.**
> This repo documents how far reverse-engineering got and is meant to save the next
> person months of dead ends. What works and what doesn't is spelled out below.

> **AI-assisted.** Much of this work (RE, driver, scripts, notes) was produced with
> an AI coding assistant. See [NOTICE](NOTICE). If you intend to upstream any of it,
> check the target project's AI-contribution policy first — some forbid it.

---

## ⚠️ Safety (read before touching the hardware)

- **NEVER `insmod spi-geni-qcom.ko` and NEVER probe the sensor's GENI SE (SE15 /
  `spi15@a9c000`) MMIO from Linux.** That SE is **TrustZone/XPU-owned**; any Linux
  MMIO access to it **hangs the whole SoC** and needs a manual power-cycle. A
  `/dev/mem` probe and a live SE read both hung the device. There is no Linux-side
  "configure the SPI" problem to solve — the TA owns the bus (see Architecture).
- Requires an **unlocked bootloader**. All on-device testing here uses
  `fastboot boot` (RAM-boot, non-persistent) — nothing is flashed; a power-cycle
  returns to the installed system.
- This is **personal reverse-engineering on my own device.** Do the same on yours.

---

## TL;DR — what's cracked, what isn't

**Works / understood:**
- The sensor SPI is driven **entirely by a TrustZone trusted app (`gfber`)**, not by
  Linux. Linux only turns on the GCC clock, toggles reset/power GPIOs, and forwards
  the touch IRQ.
- The **keymaster get-key gate**: `keymaster64` cmd `0x205` returns the FP key blob
  **only when the FPC TA `fpcber` is resident** in TrustZone first. Load `fpcber`
  once per boot and the Goodix key path unblocks.
- The full **`gfber` command ABI**: command *group* at `send_buf[0x04]`, sub-command
  at `[0x10]`, a **physically separate** payload buffer at `[0x14]`, length at
  `[0x18]`, status back at `[0x40]`. Per-command response lengths matter.
- **Cold init** end-to-end: `DETECT_SENSOR` → `INIT` → `INIT_FINISHED` (all status 0),
  and a real **sensor firmware-version read** over SPI (`Milan_v_3.01.11.02`,
  88×108 array).
- **Sensor touch verified** (power on/off control flips `DETECT` 0 ↔ 1062) and
  **IRQ-driven frame capture** on finger contact (`irq_type=0x80` IMAGE, op 39).
- The **enroll / authenticate** command map, including a **TEST path that needs no
  gatekeeper HAT** (`grp3/1060` enroll, `grp3/1061` auth).

**Does NOT work yet:**
- **No viewable fingerprint image.** Raw op39 frames are dominated by fixed-pattern
  noise with no calibration base; after FPN removal there's a finger-contact blob but
  no resolvable ridges. A clean image needs the calibration/acquire path on-device.
- **No working enroll/authenticate unlock.** The normal path carries a gatekeeper
  hardware-auth-token (HAT); whether the TA verifies it is untested. The no-HAT TEST
  path is RE'd but not yet exercised with a finger.
- **No libfprint / PAM integration** (that's the last mile once enroll/auth works).

The deep, blow-by-blow log is in [`re/notes/protocol.md`](re/notes/protocol.md)
(Findings A–V). The command-id map is in
[`re/notes/gf_cmd_map.txt`](re/notes/gf_cmd_map.txt).

---

## Architecture

```
  Linux (mainline)                 TrustZone (QSEE)              userspace (Android HAL)
  ─────────────────                ──────────────────           ───────────────────────
  goodix_fp.ko (this repo)         gfber  TA  ── all SPI I/O     libgf_hal / libgf_ca
   • power/clk/reset GPIO          fpcber TA  ── keymaster gate   (orchestration; RE'd,
   • GCC clock (NOT MMIO)          keymaster64 ── FP key 0x205     not shipped here)
   • GPIO121 touch IRQ
   • qseecom_shim.ko  ── relays QSEECom ioctls to mainline qcom_scm
```

Linux never issues an SPI transfer to the sensor. The downstream `gf_spi.c` is a
platform driver with zero `spi_*` calls — confirming the TA owns the bus. The kernel
driver's whole job is clock + GPIO + IRQ relay, plus (in this research build) driving
the `gfber` TA directly over `qcom_scm` for experimentation.

---

## Repo layout

| Path | What |
|------|------|
| `driver/goodix_fp.c`   | mainline platform/char driver + `gfber` TA command probe (sysfs). |
| `driver/qseecom_shim.c`| `/dev/qseecom` shim backing the downstream QSEECom ioctl ABI with mainline `qcom_scm`. |
| `driver/fpc_tz.c`      | earlier FPC-path experiment (kept for reference). |
| `on-device/`           | `gfload.py` (load TAs) + `enroll-probe.sh` (run the probes from a host over ssh). |
| `*.py` (gf*/kmtest*)   | iterative RE probe scripts (messy; `gf6.py` = full init + version read). |
| `re/notes/`            | the protocol RE log + command map. **Start here for the method.** |

**Not included (proprietary — do not redistribute):** the signed TrustZone blobs
(`gfber`/`fpcber`/`cmnlib` `.mdt`/`.b0*`), the vendor HIDL binary, and Qualcomm/Sony/
MiCode reference source. They are `.gitignore`d. You must extract the TA blobs from
your own device's firmware.

## Dependencies / caveats

- Built against a mainline-based **7.2.9-sdm845** tree with an out-of-tree
  `qcom_scm` extension exporting `qcom_scm_qseecom_app_send_phys`,
  `..._tzmem_alloc`, `..._alloc_image`, `..._app_get_id`, `..._app_shutdown`. These
  are **not in upstream Linux** — this driver is not upstreamable as-is.
- Clock must be `GCC_QUPV3_WRAP1_S7_CLK` + `WRAP_1_S_AHB` (SE15/S7, not S5).

## Reproduce (high level)

1. Build `goodix_fp.ko` + `qseecom_shim.ko` against the 7.2.9-sdm845 tree.
2. RAM-boot the test kernel (`fastboot boot …`; **never flash the SE-enabled DTB**).
3. `insmod qseecom_shim`; load `gfber` then `fpcber` (`on-device/gfload.py`);
   `rmmod qseecom_shim`; `insmod goodix_fp gf_app_id=<id>`.
4. `echo 1 > …/ginit` → expect `DETECT/INIT/INIT_FINISHED` status 0 + the version read.
5. Probe enroll/auth with `on-device/enroll-probe.sh` (`step4` = no-touch gating,
   `step5/6` = touch enroll/auth, reading the `trace`/`snaps` sysfs).

## Roadmap (where to pick up)

1. Run the no-touch gating probe: does the TEST enroll/auth path (`1060`/`1061`)
   dispatch pre-touch? Does `grp1/1007` with a zeroed HAT return `INVALID_HAT`
   (⇒ a real gatekeeper HAT is required)?
2. Touch enroll/auth; read the `trace`/`snaps` sysfs to pin the enroll-remaining /
   match-result irq-buffer offsets.
3. Either demo the no-HAT TEST enroll+match, or wire a gatekeeper HAT (PIN/password
   TA) for the real path.
4. Find the calibration/base command for a clean image, if one is wanted.
5. libfprint driver + PAM glue for Phosh.

## License

Kernel sources are **GPL-2.0-only** (SPDX headers in each file), matching the Linux
kernel. See [LICENSE](LICENSE). Notes and scripts are released under the same terms.
