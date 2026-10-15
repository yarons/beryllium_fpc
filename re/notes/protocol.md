# Goodix Milan-F TA (gfber) protocol — RE notes (2026-10-06)

Libs: fingerprint/re/lib64/{libgf_ca,libgf_hal}.so (aarch64, stripped, dynsyms kept).
TA: gfber, QSEE app id 4 (loads only with app-region notify). cmnlib (ELF32) prereq.

## Transport: gf_ca_invoke_command(w0 arg0, w1 arg1, x2 *buf, w3 len)
Per call:
1. alloc dma-heap buffer, len rounded up to 4K; mmap -> local `map`.
2. memcpy(map, buf, len)            # caller payload INTO dmabuf
3. QSEECom req header (64B @ ion_sbuffer+0):
     +0x00 u32 seq        # increments each call (g_ta_handle+0x10 counter)
     +0x04 u32 arg0       # w0
     +0x08 u64 timestamp  # gettimeofday ms
     +0x10 u32 arg1       # w1
     +0x14 u32 <dmabuf phys>   # patched by modified-cmd (ion_fd_info.cmd_buf_offset=0x14)
     +0x18 u32 len        # w3
     +0x44 u32 0
   resp buffer = ion_sbuffer+0x40 (64B).
   ion_fd_info.data[0] = {fd=dmabuf fd, cmd_buf_offset=0x14}
4. QSEECom_send_modified_cmd(handle, req=+0, 64, resp=+0x40, 64, &ion_fd_info)
5. on ok: memcpy(buf, map, len)     # dmabuf back OUT to caller
6. return = u32 at resp+0 (ion_sbuffer+0x40)  # 0 = ok

=> The real command lives in the dmabuf payload (buf). arg0/arg1 = still TBD
   (likely target/channel + flag). Payload struct = TBD from HAL.

## TODO
- gf_ca_open_session: TA name + QSEECom_start_app sb_size + keymaster key set.
- libgf_hal: wrapper gf_hal_invoke_command / cmd_id_table -> payload struct {cmd?,...}.
- first target: an init + a read-back (chip id / GET_CHIP_TYPE) to prove 2-way.

## HAL -> TA command format (from gf_hal_invoke_command / _ex / init_finished)
gf_hal_invoke_command(w0 cmd_id, x1 buf, w2 len) -> gf_ca_invoke_command(arg0=1, arg1=cmd_id, buf, len)
  => CA req: [+4]=1 (const), [+0x10]=cmd_id, [+0x18]=len, payload dmabuf phys @ [+0x14].
gf_hal_invoke_command_ex(cmd_id): malloc 0x60 (96) zeroed -> invoke(cmd_id, buf, 0x60). Generic no-arg cmd.
gf_hal_init_finished: malloc 0x64 (100), zero [0..0x5f], [+0x60]=0 -> invoke(cmd_id=1005/0x3ed, buf, 100).
  => TA cmd ids are 1000-based (GF_CMD_* = 0x3e8 + n). INIT_FINISHED = 1005.
Payload = ~96-byte struct, zeroed in; TA fills it + status. status also at CA resp+0.
NOTE: gf_hal_chip_info / get_fw_info use /dev kernel-driver IOCTL (0x4008670d, 0x8001670b),
  NOT TA commands -> need goodix char driver for those; skip, use TA cmds only.

## kernel repro plan
Reuse fpc_tz power/clock/reset/irq + app_send_phys. Goodix req (differs from FPC):
  m32[0]=seq(0) m32[1]=1 m32[2,3]=ts(0) m32[4]=cmd_id m32[5]=payload_phys m32[6]=len
  resp @ req+0x40 (status u32). payload dmabuf zeroed, read back after.
First test: load gfber (app 4), send INIT_FINISHED (1005). Expect status!=transport-err => 2-way proven.
Full init (customize/config/otp/calibrate) still TBD before capture/enroll.

## STATUS 2026-10-06: kernel<->TA transport WORKS (scm=0)
- tzmem pool buffers are mandatory (raw DMA => scm=-22). fpc_tz gf_send + gcmd sysfs.
- gfber app loads (flaky; retry). cmd 1005/1000/1001/9999 -> scm=0 result=0 status=0,
  payload all-zero. status(resp+0)=CA/SMC level; real per-cmd result is in the PAYLOAD
  (CA copies dmabuf back out). Need a data-returning cmd to prove dispatch.
- HAL ops are a Milan-F vtable at g_hal_function (GOT 0x3b000+0x860):
    +0x48  get_auth_id
    +0xd0  invoke_command (generic: arg0=1, arg1=cmd_id)
    +0x100 get_id_list
  Per-op cmd ids live inside hal_milan_f_series_* funcs (next disasm layer).

## NEXT STEPS (ordered)
1. Disasm hal_milan_f_series_user_invoke_command / _customize / function_init:
   extract init sequence + cmd ids + payload structs.
2. Reproduce init (config blob + OTP from /persist + calibration) -> a data-returning
   cmd (chip id / version) to prove dispatch end-to-end.
3. capture -> enroll -> template store/load (auth id, HAT via keymaster).
4. Phosh/PAM glue (libfprint driver or custom).
Big multi-session effort; no open reference for Goodix Milan-F TA.

## INIT HANDSHAKE fully RE'd (2026-10-06, from gf_hal_reinit + gf_ca_open_session)
Order (gf_hal_reinit @0x1a3b0):
 1. gf_hal_control_spi_clock(1)  -> ioctl /dev/goodix_fp GF_IOC_ENABLE_SPI_CLK = 0x40046705
 2. gf_ca_close_session(); gf_ca_open_session():
      - QSEECom_start_app("gfber", sb_size 0x1000)  [kernel: QSEOS_APP_START, needs region notify]
      - get_key_from_keymaster(buf,256): keymaster64 (app 1) QSEECom_send_cmd req8 {0x205,0x02}
        -> raw 256-B keymaster response buffer
      - gf_ca_invoke_command(arg0=2, cmd_id=109/0x6d, buf256, 256)  == KEY-SET to TA
 3. gf_ca_invoke_command(arg0=1, cmd_id=1000, buf356, 356)  == init; returns 260 B @ payload+0x60
Other HLOS->driver ioctls (downstream gf_spi.c, /dev/goodix_fp):
   GF_IOC_RESET=0x6702, GF_IOC_ENABLE_SPI_CLK=0x40046705, GF_IOC_DISABLE_SPI_CLK=0x6706,
   GF_IOC_CHIP_INFO=0x4008670d, GF_IOC_... (chip/fw via ioctl, not TA).
Vtable (g_hal_function @ GOT 0x3b000+0x860) slots: +0x48 get_auth_id(0x2d550),
   +0xd0 invoke_command(0x2d9cc, validates len>=0x60, forwards cmd_id to gf_ca),
   +0x100 get_id_list. Per-cmd ids inside hal_milan_f_series_* funcs.

## IMPLEMENTED in fpc_tz (dist/qsee11): SE clock + keymaster(0x205) + setkey(cmd109 arg0=2) + cmd1000.
All SMC calls succeed (scm=0 result=0). BUT:
  - keymaster 0x205 returns km[0]=0xff000fff (FPC path to SAME keymaster gave status=0/off12/len152)
    -> key blob may be malformed; TA keyed with it returns status 0 (accepts) but...
  - cmd 1000 (init) returns status 0 but EMPTY payload (no 260-B sensor info).
=> FRONTIER: cmd 1000 needs the sensor reachable over SPI, which needs the full downstream
   Goodix char driver (gf_spi.c) setup via its ioctls (clock set + reset), not just the single
   gcc s5 clock + a reset pulse. Next phase = port gf_spi.c (/dev/goodix_fp) to mainline:
   enable the FULL SPI clock set GF_IOC_ENABLE_SPI_CLK touches, the reset/IRQ state machine,
   then re-try cmd 1000. Also re-check the keymaster 0x205 blob (0xff000fff). Big driver-port task.

## gf_spi.c PORT DONE + WORKING (2026-10-06)
mainline driver: fingerprint/driver/goodix_fp.c (342 lines; built via build-env/qsee3.sh).
Platform driver, compatible "goodix,fp-milanf"; DT node in beryllium-common:
  reset-gpios tlmm37 (active low), irq-gpios tlmm121, vdd-supply fp_vdd,
  clocks = core_clk(GCC_QUPV3_WRAP1_S5_CLK), iface_clk(GCC_QUPV3_WRAP_1_S_AHB_CLK).
Creates /dev/goodix_fp (misc). ioctls verified on HW (dist/qsee12):
  ENABLE_POWER 0x6707, RESET 0x6702, ENABLE_SPI_CLK 0x40046705 (-> s5=on, ahb refcnt+),
  ENABLE_IRQ 0x6703 (irq 226 registered, firing). IRQ -> netlink unit 25 (GF_NET_EVENT_IRQ=1).
NOTE: port does NOT change cmd-1000 result by itself — the core+iface clocks were already
effectively on (ahb globally, s5 via fpc_tz). cmd-1000-empty blocker is elsewhere:
  (a) keymaster 0x205 blob 0xff000fff (suspect), and/or
  (b) the SPI SE config for TZ use / full HAL command sequence.

## TWO PATHS from here
A) Kernel TA path: merge TA-talk (gf_send/setkey/cmd1000 from fpc_tz) into goodix_fp,
   reproduce exact HAL init order (power/reset/clk/irq around cmd 109 + 1000), fix keymaster blob.
B) Userspace vendor HAL path (more likely to yield working enroll/auth): now have /dev/goodix_fp;
   still need a /dev/qseecom shim for libQSEEComAPI + libhybris to run fingerprint.goodix.so.

## PATH 1 INTEGRATION DONE (2026-10-06): goodix_fp does the full handshake, cmd 1000 still empty
fingerprint/driver/goodix_fp.c now integrates the TA path (built dist/qsee15):
  probe allocs tzmem (gfber cmds) + dma (keymaster) buffers; sysfs ginit/gcmd/gdump.
  ginit = regulator_enable + gf_clk_enable(core+iface) + gf_hw_reset + irq enable
          + gf_ta_setkey (keymaster 0x205 via DMA -> raw 256B -> cmd109 arg0=2 via tzmem)
          + gf_ta_send(1,1000,356).
Results (HW): keymaster app id=1 (looked up), keymaster(0x205) -> km_rsp[0]=0xff000fff
  (same via dma OR tzmem, rsp offset 0x100 OR 0x1000 -> identical; so NOT a buffer bug).
  setkey cmd109 -> status 0. cmd 1000 -> status 0 but payload EMPTY (no 260B sensor info).
UNEXPLAINED: earlier FPC keymaster_init (same app 1, same 0x205, same session) returned
  status=0/off12/len152; goodix keymaster returns 0xff000fff. Possibly 0xff000fff is a valid
  encrypted-key first word (get_key_from_keymaster does NOT validate it, just forwards 256B).
CONCLUSION: all SMC/TA calls succeed; the remaining wall is that the TA cannot read the
  sensor over SPI. The TA does SPI through the GENI SE (qup1 SE5 / wrap1_s5), which on mainline
  is never configured for SPI protocol (no spi-geni bound -> no GENI SPI firmware loaded in the
  SE; pins 81-84 are XPU-protected so a Linux SPI master hangs). Downstream gf_spi is platform-
  only and does not configure the SE either -> on Android the SE SPI setup came from the
  bootloader/TZ path that mainline doesn't trigger.
=> HARD FRONTIER. Options:
   (i)  GENI SE SPI bringup for TZ use: load GENI SPI firmware into wrap1_s5 SE MMIO from Linux
        WITHOUT muxing pins 81-84. Deep, risky (XPU), uncertain.
   (ii) PATH 2 userspace vendor HAL: /dev/goodix_fp done; add /dev/qseecom shim + libhybris to
        run fingerprint.goodix.so (it drives the same SE via the same ioctls + QSEECom). Large
        but uses Goodix's own tested SE/TA sequence -> most likely to actually work.

## PATH 2: /dev/qseecom SHIM — core WORKING (2026-10-06)
fingerprint/driver/qseecom_shim.c (misc /dev/qseecom), built via build-env/qsee3.sh (dist/qsee17).
Backs the downstream QSEECom ioctl ABI with the mainline qcom_scm qseecom calls.
HW-verified (over USB; test kernel #19):
  - GET_QSEOS_VERSION (0xC004970A) -> 0x1400000.
  - LOAD_APP (0xC0549707, name "gfber") -> app_id 3. Loads cmnlib (services) first,
    APP_START retry, and treats APP_ALREADY_LOADED(-38) / name-lookup as success.
  - mmap -> vmalloc_user shared buffer; SET_MEM_PARAM (0xC0189708) records user base.
  - SEND_CMD (0xC0209703): offsets within sb -> bounce whole sb into per-handle tzmem ->
    app_send_phys(TZ_APPS cmd1) -> copy back. Verified reaching gfber (svc=0 cmd=1
    status=0 result=0 data=0x3). tzmem bounce is what makes gfber accept it.
Design: userspace sb = vmalloc_user (mmap via remap_vmalloc_range); every SMC bounces
  through a tzmem buffer (gfber rejects non-tzmem). ioctl numbers are _IOWR(0x97,...).
REMAINING for a full HAL:
  1. SEND_MODFD_CMD (ioctl 4, _IOWR(0x97,4,...)): resolve each ifd_data[].fd (dma-buf from
     dma-heap) -> phys, copy its contents into a tzmem payload, patch that phys into the cmd
     buffer at cmd_buf_offset, build the sglist (whitelist). This is what the real Goodix
     commands (cmd 1000, 109) need (they pass a payload via send_modified_cmd). STUBBED (-ENOSYS).
  2. Listener RECEIVE/SEND_RESP (ioctl 5/6): the FP TA may raise listener requests; currently no-op.
  3. libhybris + bionic deps to run fingerprint.goodix.so / libgf_* / libQSEEComAPI on musl.
Then: HAL enroll/auth -> libfprint/PAM glue for Phosh.

## SEND_MODFD_CMD DONE + WORKING (2026-10-06, dist/qsee20)
qseecom_shim.c SEND_MODFD_CMD (_IOWR(0x97,4,64) = 0xC0409704):
  - bounce shared buf -> per-handle tzmem (h->tz);
  - for each ifd_data[i].fd>0: dma_buf_get -> begin_cpu_access -> dma_buf_vmap -> copy the
    dma-buf contents into a 2nd per-handle tzmem (h->aux) at a 4K-aligned offset;
    patch lower_32(aux_phys+off) into the cmd buffer at req_off+cmd_buf_offset (u32);
  - app_send_phys(TZ_APPS cmd1, no sglist) -> copy aux payload back to the dma-buf -> copy sb back.
  needs MODULE_IMPORT_NS("DMA_BUF"). System dma-heap buffers are non-contiguous -> we vmap+copy
  into tzmem (don't use the dma-buf's own phys), which also satisfies gfber's tzmem requirement.
HW-verified: LOAD gfber -> mmap -> SET_MEM -> SEND_MODFD (payload = dma-heap buf, cmd_buf_offset
  0x14) reached gfber: svc=0 cmd=1 status=0 result=0 data=0x3. Payload resolve+patch+roundtrip OK.
ABI GOTCHA: struct qseecom_send_modfd_cmd_req ifd_data[] is 4-byte aligned -> sits at OFFSET 28
  (after resp_len@24), not 32; total struct 64 (tail pad). Userspace must pack ifd at 28.
SHIM STATUS: GET_VERSION, LOAD_APP(+cmnlib/retry/already-loaded), SET_MEM_PARAM, SEND_CMD,
  SEND_MODFD_CMD all working. Listener RECEIVE/SEND_RESP still no-op.
REMAINING for working FP: (1) listeners if the TA raises them; (2) libhybris + bionic to run
  fingerprint.goodix.so/libgf_*/libQSEEComAPI on musl; (3) HAL enroll/auth -> libfprint/PAM (Phosh).

## libhybris SCOPE + status (2026-10-06)
Deps of the Goodix HAL (readelf -d): libgf_hal->libgf_ca->libQSEEComAPI + libcutils, liblog,
  libutils, libbinder, libqti-perfd-client, libc++, bionic libc/m/dl, libhardware, libhidl*.
  fingerprint.goodix.so = 32-bit HIDL HAL; 64-bit libgf_hal.so present (exports gf_hal_*) =>
  drive it DIRECTLY (skip HIDL/binder/hwservicemanager), 64-bit.
Android libs pullable from MIUI (Android 10 APEX): libc in com.android.runtime apex, etc.
No hybris in Alpine/pmOS -> build mer-hybris/libhybris for aarch64/musl.
Steps: build hybris; assemble 64-bit lib set; stub libbinder/libqti-perfd-client + property
  service; harness android_dlopen(libgf_hal) + RE'd init + enroll/auth; provide /data/vendor/
  goodix + OTP + firmware; libfprint/PAM glue. Effort: weeks (targeted Halium).
** GATING ISSUE: the GENI SE (wrap1_s5) SPI config wall blocks BOTH the kernel path AND the HAL.
   hybris does not fix it. Solve SE SPI first, else the HAL hits the same empty sensor reads. **

## OFFLINE WORK 2026-10-07 (device down, awaiting power-cycle)
### Finding A — keymaster 0x205 is FAILING (concrete blocker, corrects earlier guess)
get_key_from_keymaster tail: after send_cmd it does `w8 = rsp[0]; if (w8==0) success else "get key failed"`.
=> rsp[0] is the STATUS and MUST be 0. Our keymaster(0x205) returns rsp[0]=0xff000fff != 0 = ERROR.
So the Goodix TA is keyed with a FAILED blob (gf_ta_setkey forwards it unchecked) -> TA not keyed ->
cmd 1000 noops. (Earlier FPC keymaster_init logged status=0/off12/len152 = success; same app1/cmd0x205.
Unresolved why Goodix call fails: candidates = bootloader keymaster(app1) vs HAL fresh start_app
instance; 0x205 may need the caller to be the FP TA / provisioning not present; or request needs
more than {0x205,0x02}. The HAL LOADS keymaster64 via start_app (own SB) rather than reusing app1.)

### Finding B — SE7 (not SE5) + safe bring-up prepared (dist/qsee23)
GPIO 81-84 = qup_spi15 = spi15@a9c000 = SE7 = GCC_QUPV3_WRAP1_S7_CLK (was wrongly clocking SE5).
mainline geni-se CAN load SPI firmware: spi_geni_init reads proto; if GENI_SE_INVALID_PROTO ->
geni_load_se_firmware(SPI) (request_firmware from wrapper "firmware-name"); if SPI -> already set.
v23 (dist/qsee23) prepared: &spi15 status=okay, pinctrl + dmas DELETED (pins untouched = no TLMM
XPU hang; FIFO mode); firmware-name="qcom/sdm845/Xiaomi/beryllium/qupv3_fw.elf" on &qupv3_id_1;
CONFIG_SPI_QCOM_GENI=m (manual insmod, no boot auto-probe). The /dev/mem probe hung because it
lacked PM/ICC votes; the driver does those first, so spi-geni probe should read proto SAFELY.

### Finding C — EXPERIMENT A IS DEAD: SE15 is TrustZone-owned; Linux never drives the SPI (2026-10-08)
Offline proof from downstream (fingerprint/downstream/):
- DT fingerprint_goodix node (beryllium-p0.dtsi:134) is IRQ-only: compatible "goodix,fingerprint",
  gpio-reset tlmm37, gpio-irq tlmm121, fp-gpio-pwr tlmm94. NO spi bus, NO reg, NO clocks, NO SE ref.
- Downstream enables se10/se8/se3/se5/se14/se6/se9 but NEVER se15 / spi15 / a9c000. SE15 absent.
- Downstream driver gf_spi.c registers a platform_driver (not spi_driver; the spi_driver is #if0'd).
  It has clk_prepare_enable(core_clk/iface_clk) + reset/pwr GPIO + IRQ->netlink. ZERO spi_sync/
  spi_write/spi_read/spi_transfer anywhere. Linux NEVER does an SPI transfer to the sensor.
=> The sensor SPI (SE15) is driven entirely by the TZ TA. Linux's ONLY job vs the SE is to turn on
   its GCC clock (clk framework, NOT MMIO) via ENABLE_SPI_CLK, plus GPIOs + IRQ forward.
=> Probing SE15 MMIO from Linux (insmod spi-geni) is an XPU-protected access = SoC HANG, same root
   cause as the /dev/mem hang. There was never a Linux-side "SE config" problem to solve. DROP A.
   DO NOT boot v23/qsee23: it HUNG at boot (2026-10-08: ~110s no network, fell back to installed r1).
   Likely cause: udev modalias autoload of spi-geni-qcom.ko onto the enabled SE15 node (NOT inert as I
   first thought), and/or firmware-name request_firmware stall. USE qsee22 (spi15 disabled, S7 clock, no
   firmware-name) for all tests.
The S7 clock fix (core_clk=GCC_QUPV3_WRAP1_S7_CLK, iface=WRAP_1_S_AHB) IS still needed+correct: it is
the clock the TA's SPI runs on; must be enabled (ENABLE_SPI_CLK) BEFORE cmd 1000. Verified in v23 DTB.

## TEST PLAN (device up 2026-10-08) — keymaster is the ONLY blocker
0. Verify clean installed r1 (DONE: uname 7.2.9-sdm845, MODS_CLEAN).
1. fastboot boot dist/qsee23/boot-fc.img (RAM, non-persistent). Wi-Fi may drop -> poco-usb.
2. Load qseecom_shim.ko. Run kmtest.py: keymaster64 (fresh load + app1 lookup), SEND_CMD {0x205,0x02},
   read the FULL {status,offset,length} triple at resp base. Interpret vs FPC success (status=0/off12/
   len152): status==0 = real key blob follows at `offset`; status!=0 = "get key failed" per disasm.
   0xff000fff with off/len=0 => error; 0xff000fff AS the key[0] with sane off/len => it was a misread.
3. If keymaster OK: port exact req/rsp into gf_ta_setkey (check status==0), enable SE clock, reset/pwr,
   re-run ginit -> cmd 1000 should return 260B at +0x60. Then enroll/auth.
4. DO NOT insmod spi-geni-qcom.ko (would hang the SoC; SE is TZ-owned — see Finding C).

### Finding D — keymaster 0x205 CONFIRMED hard-fail on-device (2026-10-08, qsee22 RAM-boot)
Ran kmtest.py via /dev/qseecom shim on qsee22 (clean S7 image, spi15 disabled). Results:
  LOAD keymaster64 -> app_id=1 (bootloader already loaded it)
  SEND {0x205,0x02} len8 -> status=0xff000fff offset=0 length=0  (raw ff0f00ff 00000000...)
  SEND {0x205,0x00}      -> status=0xffffffda (-38)
  dmesg: qseecom raw svc=0 cmd=1 status=0 result=0 type=0xee01 data=0x1  (SMC itself SUCCEEDED; the
         TA ran and returned the error in the response body).
Wrong-offset hypothesis REJECTED: the response triple is clean {status=0xff000fff, off=0, len=0}.
Disasm of get_key_from_keymaster (libgf_ca.so @0x284c) CONFIRMS my test is faithful:
  - QSEECom_start_app(path="/firmware/image", name="keymaster64"@0xfa0, sb=0x1000)  [name verified = keymaster64]
  - req = 8 bytes: x8 = 0x205 | (0x2<<32) -> {u32 0x205, u32 0x02}  [exactly what kmtest sends]
  - resp buffer = caller outbuf; reads resp[0]=status, resp[1]=off, resp[2]=len
  - 0x2a14 `cbz w8,success`: status==0 => success; else log "km get key ... rsp.status:0x%x" +
    shutdown_app + return 1015. So status MUST be 0; 0xff000fff = hard fail. Tag [goodix_keymaster].
  - The HAL does NO separate keymaster "configure" before 0x205 (start->send->shutdown is self-contained).
=> keymaster64 cmd 0x205 (Xiaomi OEM fp get-key extension) genuinely refuses on this device.
PRIME HYPOTHESIS: keymaster64 lacks its Root of Trust (the bootloader's one-shot KM_SET_ROT at boot
  sends verified-boot key hash + lock state; pmOS/lk2nd never sends it), so OEM key ops fail. This is
  a boot-time precondition, not a HAL/request bug. Corrects old note claiming FPC path got status=0 on
  same app1/0x205 (unverified; current primary evidence is authoritative).
NEXT localizing test: run a STANDARD keymaster cmd (version/add_rng/generate) via shim. If standard
  cmds ALSO fail -> keymaster globally unprovisioned (ROT missing) = likely hard wall (needs lk2nd ROT).
  If only 0x205 fails -> key/command-specific (maybe per-device fp keyblob provisioned under Android only).

### Finding D-final — request shape IRRELEVANT; wall = keymaster unconfigured/unprovisioned (2026-10-08)
Swept {req_len 8|64} x {rsp_len 256|1024} with {0x205,0x02,0,zeroed tail} via shim: ALL FOUR return
identical status=0xff000fff off=0 len=0 (SMC status=0 result=0 type=0xee01 each). So the FPC
"status=0" note is NOT reproducible; keymaster64/app1/cmd 0x205 is an invariant TA-level refusal.
Localization (what is NOT the problem): SE/SPI (TZ-owned, fine), transport (shim reaches TA, scm=0),
request/response sizing (irrelevant), app identity (app1 == keymaster64, verified by app_get_id + disasm).
Positive HW signals: fpc_tz probe enabled SE clk @19.2MHz and the sensor fired IRQs (#1/#2/#3) on reset
=> power/reset/clock/irq path to the sensor WORKS.
Root cause (high confidence): keymaster64 is UNCONFIGURED/UNPROVISIONED on pmOS. Evidence: `ps` shows NO
keystore/keymaster/hwservice running (Android's keystored normally calls KM configure(OS_ver,patchlevel)
at boot; bootloader sends Root-of-Trust). Vendor has libqtikeymaster4 (KeymasterHalDevice::configure),
libkeymasterprovision (ProvisionDeviceId/AttkKeyPair), KeymasterUtils::send_cmd/qseecom_dev_init. The fp
HAL (libgf_ca get_key_from_keymaster) only GETS the key, never provisions; provisioning/config is the
keystore/bootloader's job, absent under pmOS. So the OEM fp get-key (0x205) is refused.
### Finding E — keymaster 0x205 UNBLOCKED: precondition is fpcber resident (2026-10-08) **KEY FIX**
The ROT/unconfigured theory was WRONG. kmtest2.py on the live qsee22 boot proved the gate empirically:
  keymaster64 0x205 ALONE          -> 0xff000fff FAIL
  after loading gfber (app5)       -> 0xff000fff FAIL
  after loading fpcber (app6)      -> status=0 offset=12 length=152  SUCCESS  (152-byte key blob)
=> The precondition is that the FPC TA **fpcber** is LOADED/RESIDENT in TZ before the keymaster get-key
   (cmd 0x205). gfber (Goodix TA) does NOT satisfy it; fpcber specifically does. This exactly matches the
   Oct-6 successes, where fpcber was app 2 (loaded by the fpc_tz probe path) and keymaster returned 152B.
   Today's earlier failures were simply a fresh boot with no fpcber loaded yet.
   (Why fpcber unlocks a key the Goodix path uses: keymaster's OEM get-key likely checks that a registered
   fingerprint TA exists; fpcber registration satisfies it. The 152B key is generic FP key-data.)
RESIDENCE: the shim's UNLOAD_APP is a no-op (TZ keeps the app), so loading fpcber ONCE per boot (even via a
closed handle) leaves it resident for all later keymaster calls, including goodix_fp's gf_ta_setkey.
SEQUENCE for the Goodix reader (per boot): load gfber -> load fpcber -> keymaster 0x205 (now returns key)
-> feed key to gfber cmd 109 (setkey) -> gfber ginit / cmd 1000 -> sensor data.
VERDICT UPDATE: keymaster wall REMOVED. SE dead-end cleared, sensor HW path alive (SE clk 19.2MHz + IRQs on
reset), transport works, keymaster key now obtainable. Next: drive the full Goodix init with fpcber resident
and see if cmd 1000 returns sensor data (the remaining unknown).

### Finding F — full keyed chain WORKS; cmd 1000 moves no data (2026-10-08) **MILESTONE**
With fpcber resident, drove goodix_fp.ko (gf_app_id=5 gfber, km_app_id=1): `echo 1 > ginit`:
  keymaster(0x205) -> scm=0 km_rsp=00000000 0000000c 00000098 <REDACTED key bytes>  (status0/off12/len152 + key)
  setkey (cmd109 arg0=2) -> scm=0 result=0 status=0   (gfber ACCEPTED the key)
  cmd 1000 init -> 0  p60=0 0 0 0
gdump: the ENTIRE gfber response buffer (0x000-0x180) is ZERO. So cmd 1000 (the init) executes with scm=0 but
writes no data back. goodix_fp log also: "goodix_fp ready: irq 226, core_clk 19200000 Hz" (clock on).
=> keymaster + setkey are SOLVED. New frontier: does the TZ-owned SE15 SPI actually move data to/from the
   sensor? cmd 1000 all-zeros could be (a) init returns no payload (benign) or (b) the TA's SPI read is empty.
NEXT: send the gfber chip-id / get-version command (HAL has gf_hal_chip_info, GF_CMD_TEST_PRE_GET_VERSION,
   GF_CHIP_3266) via the gcmd sysfs and check for a real chip id. Nonzero chip id => SPI-to-sensor works
   (very close). Zero => SE15 SPI not moving data (maybe bootloader/TZ never set SE15 SPI proto on this
   fastboot-boot path; re-opens the SE-config question from the TA side, NOT via Linux MMIO). Need the exact
   gfber cmd number for chip-info from libgf_hal disasm (gf_hal_chip_info -> gfber cmd id).

### Finding G — gfber command format is WRONG; TA returns 0 to everything (2026-10-08) **CORRECTION**
Control test via gcmd on the keyed gfber: cmd 61453 (bogus) -> status 0; cmd 1000:356 -> 0; cmd 1000:4
(bad len) -> 0. ALL identical status=0, payload all-zero. A real dispatcher would reject a bogus cmd id.
=> The gfber wire format currently used (req64 {m[1]=arg0, m[4]=cmd_id, m[5]=payload_phys, m[6]=len};
   resp64 status@+0x100; payload@+0x200) is NOT what gfber parses. The TA takes the SMC but does not
   dispatch my command — it returns a default 0 and writes nothing. Therefore the earlier "setkey status=0"
   and "cmd 1000 -> 0 success" were NEVER real command processing (setkey status=0 appeared 14x historically
   including with the bad keymaster blob = non-discriminating), and the keymaster fix (Finding E), while
   genuinely correct, does NOT advance the sensor path by itself.
HONEST STATE: keymaster get-key works (real 152B key). Everything past it (gfber setkey, init, any sensor
   read) is UNVERIFIED because the gfber command ABI is not yet correctly RE'd. The real next task is to
   disassemble libgf_ca's gfber send path (gf_ca_send_command / the QSEECom_send_cmd wrapper gfber uses) and
   derive the TRUE request/response layout + the cmd id for a read-back command (chip-id/version). Only a
   nonzero chip-id read proves the TA dispatch + the SE15 SPI link. Also unresolved: residence vs latch of
   fpcber (LOAD fpcber now EINVAL; gfber=5, km=1 resolve). Not close to a working reader.

### Finding H — the REAL gfber ABI = QSEECom send_modified_cmd + /dev/ion payload (2026-10-08)
Disassembled gf_ca_invoke_command (libgf_ca @0x231c). The true gfber command path:
  1. open("/dev/ion"); ION_IOC_ALLOC (ioctl 0xc0204900, len rounded to page); map; also uses 0xc0084902
     (share/map) and 0xc0044901 (free). String "Error::ION FREE ioctl" / "Error::while trying to allocate".
  2. build the command, then "gx_ta_send_modified_cmd_req" = QSEECom_send_modified_cmd (the send_modfd
     path) which embeds the ION buffer fd/phys into the request at a modfd offset. Logs
     "[goodix_ca_entry] begin token %d, cmd_id=%d". Response token/status read from handle+0x40 / +0x44.
=> My goodix_fp gf_ta_send used a FLAT app_send_phys with a guessed layout (m[4]=cmd, m[5]=payload_phys,
   m[6]=len). That is NOT gfber's ABI, so gfber ignores it and returns default 0 (Finding G). The correct
   path is send_modified_cmd with a separate ION/dma-buf payload whose fd is patched into the cmd struct.
REAL NEXT TASK (substantial, well-defined): replicate gf_ca_invoke_command via the shim's SEND_MODFD_CMD
   (already implemented): alloc a dma_buf, build the gfber request with the modfd fd-reference at the right
   offset + cmd_id, send_modfd, read token/status at the HAL's offsets. Need to finish RE'ing the request
   struct layout (cmd_id offset, the modfd ifd offset, response token offsets) from gf_ca_invoke_command
   0x2580/0x278c. Only then can any gfber command (chip-id, init, capture) actually dispatch.
### Finding H2 — the TRUE gfber wire ABI (from gf_ca_invoke_command disasm, 2026-10-08)
gf_ca_invoke_command(w0=cmd_id, w1=arg1, x2=data, w3=len):
  - alloc /dev/ion buffer (page-rounded len); mmap; memcpy(ion_buf, data, len)  [input payload in ION buf]
  - send_buf = QSEECom handle sb (64B). Fields (word offsets):
      [0x00] = seq counter (g_ta_handle+0x10, increments per call; 0 likely fine)
      [0x04] = cmd_id
      [0x08] = token (gettimeofday/localtime-derived; likely any value ok)
      [0x10] = arg1 (w1; 0 for most)
      [0x14] = ION payload phys  <-- PATCHED by modfd (cmd_buf_offset = 0x14)
      [0x18] = payload len
  - QSEECom_send_modified_cmd(handle, send_buf, 64, resp_buf=send_buf+0x40, 64, ifd_info)
      ifd_info[0] = { fd = ion_fd, cmd_buf_offset = 0x14 }
  - on return: resp status = send_buf[0x40] (0=success), send_buf[0x44] = aux; RESPONSE DATA is in the ION
    buffer (memcpy'd back to caller's `data`). Logs "[goodix_ca_entry] begin token %d, cmd_id=%d",
    "gx_ta_send_modified_cmd_req success/fail teeRet=%d".
REPLICATE via shim SEND_MODFD_CMD: cmd_req_buf = 64B {[0x04]=cmd_id,[0x18]=len, [0x14]=placeholder},
  resp at +0x40, ifd_data[0]={payload_dma_buf_fd, 0x14}; payload dma_buf holds input + receives response.
  Needs a dma_buf allocator on device (/dev/dma_heap/system on mainline, or /dev/ion). cmd ids: init=1000;
  need chip-id/get-version id from libgf_hal (gf_hal_chip_info). My goodix_fp gf_ta_send is WRONG
  (cmd_id@0x10 not 0x04, flat payload not modfd-ION, status@0x100 not 0x40) -> rewrite or drive via shim.

### Finding I — correct ABI VALIDATED (dispatch works); setkey rejects key with 1010 (2026-10-08)
Implemented the true ABI via shim SEND_MODFD (gftest2.py) + /dev/dma_heap/system payload:
  keymaster 0x205 -> status=0 off=12 len=152 (key OK, fpcber latched resident)
  SETKEY (cmd_id=2, arg1=109, payload=256B keymaster response) -> status=1010
  INIT   (cmd_id=1000)                                          -> status=1003
  BOGUS  (cmd_id=0xBEEF)                                        -> status=1003
=> The TA now DISPATCHES and DIFFERENTIATES commands (setkey->1010 != init/bogus->1003), proving the ABI
   (modfd + dma_buf payload, send_buf[0x04]=cmd,[0x10]=arg1,[0x14]=payload phys,[0x18]=len, status@[0x40])
   is CORRECT. Setting send_buf[0x00]=seq and [0x08]=token did not change 1010.
PRECISE BLOCKER: gfber setkey (cmd2/arg109) returns 1010 = key rejected (so init stays 1003 = unkeyed).
   The setkey payload is the raw keymaster response {status,off,len,key@12} exactly as the HAL passes it
   (open_session passes get_key_from_keymaster's buffer straight into invoke, no transform — verified).
NOTE from disasm: open_session does NOT check the setkey return (0x2214 mov w0,wzr right after), and real
   sensor ops come later via gf_hal_* with their own cmd_ids. My "cmd 1000" init is a GUESS and likely wrong.
NEXT (two concrete steps): (1) map the REAL cmd_ids/arg1 from libgf_hal's gf_ca_invoke_command call sites
   (the true init/chip-info/capture sequence) instead of guessing 1000; (2) clean COLD RAM-boot qsee22 and
   replay the whole recipe once (gfber+fpcber fresh, keymaster, setkey, real-init) to rule out a wedged TA
   state from this session's probing. Then resolve 1010 (key format / missing pre-step). Tools ready:
   gftest2.py (parameterize cmd_id/arg1), kmtest2.py. fpcber residence is latched (LOAD EINVAL but keymaster
   still returns the key).

### Finding J — cmd_id=1 is the GROUP; TA returns REAL DATA (2026-10-08) **BIG**
Mapped the real command map from libgf_hal gf_ca_invoke_command call sites:
  gf_hal_open          -> invoke(cmd_id=1, arg1=1000)            [INIT]
  gf_hal_reinit        -> cmd_id=1, arg1 in {1000,1001,1004,1005} [reinit sequence]
  gf_hal_common_user_invoke_command -> cmd_id=2, arg1=var         [keymaster/user; setkey=2/109]
  gf_hal_common_dump_invoke_command -> cmd_id=4, arg1=var         [dump]
  gf_hal_milan_f_series_function_customize -> cmd_id=1, arg1=var  [Milan-F = OUR sensor chip init]
=> cmd_id=1 is the command GROUP, arg1 is the real sub-command. My earlier "cmd 1000" sent cmd_id=1000
   (unknown group -> 1003). CORRECT init = cmd_id=1, arg1=1000.
Re-ran gftest2 with correct group:
  INIT  cmd1/arg1000 -> status=1062  payload=00000000 e8030000(=1000) 33000000 26040000 33000000 33000000
  SETKEY cmd2/arg109 -> status=1010  payload echoes keymaster resp {0,12,152,key...}
  REINIT cmd1/arg1001 -> status=0 (SUCCESS)  payload=00000000 e8030000 33000000 00000000 33000000 33000000
  REINIT cmd1/arg1004 -> status=1070
  (cmd1/arg1005 -> python harness error, not TA)
=> THE TA IS FULLY RESPONSIVE and returns REAL structured data (not zeros): payload looks like
   {u32 r0=0, u32 cmd_echo=1000, u32 0x33, u32 status_echo, 0x33, 0x33}. Different sub-cmds give different
   status (1062/1010/0/1070) = full dispatch. This is the biggest advance: the Goodix TA now talks back.
REMAINING: (1) find the correct INIT SEQUENCE / order of cmd1/argN (and the Milan-F customize sub-cmds)
   that leaves the sensor initialized (1062/1070 are "needs-something" statuses; 1001 succeeded). (2) resolve
   setkey 1010 (may or may not matter for init). (3) then the capture/image + enroll/auth commands. The
   gfber protocol is now open and the TA responds; this is iterative RE from here, not a wall.

### Finding K — init recipe + architecture fully mapped (2026-10-08)
gf_hal_open ordered sequence (the real init recipe):
  device_open(/dev/goodix_fp) -> enable_power -> get_fw_info -> reset_chip -> gf_ca_open_session(KEY:
  keymaster+setkey cmd2/109) -> control_spi_clock -> gf_ca_invoke_command(cmd1/arg1000 INIT) ->
  gf_hal_function_init (= milan_f_series_function_customize for OUR chip).
gf_hal_get_fw_info = ioctl 0x8001670b on the char driver (_IOR 'g',11) — NOT a TA/SPI read (so not a
  clean SPI proof-of-life; the real sensor comms are the TA cmd1/argN commands).
milan_f_series_function_customize (~10KB) = the chip bring-up: get_fw_info, reinit, reset_chip, plus
  calibration, nav-config, timers, key/nav events, and many cmd1/argN invokes with config-table payloads.
ARCHITECTURE (complete): kernel char driver (power/reset/irq/clock + ioctls; my goodix_fp.ko does these) +
  TrustZone gfber TA (ALL SPI sensor I/O + crypto) + userspace HAL (orchestration). Cracked: keymaster key,
  TA command ABI (modfd+/dev/dma_heap payload), command grouping (cmd1=main/argN sub, cmd2=user/key,
  cmd4=dump), and the TA responds with real data. REMAINING to a working reader = replicate the HAL's full
  orchestration: open_session key (setkey 1010 still open), cmd1/arg1000 init, then the ~10KB milan_f
  calibration/config/nav sequence (with its config-table payloads), THEN capture/image, THEN enroll/auth +
  template store, THEN libfprint/PAM. This is a large sustained RE project (days–weeks), not a few steps.

### Finding L — goodix_fp driver rewritten to TRUE ABI; device hung on reboot (2026-10-09)
Rewrote goodix_fp.c to the correct gfber ABI (staged in dist/qsee22/goodix_fp.ko, 549408 bytes, built
2026-10-09 07:00):
  - gf_ta_send_io(cmd_grp, arg1, len, in, inlen): req@gf_mem+0 {[0x04]=cmd_grp,[0x10]=arg1,[0x14]=payload
    phys (gf_mem+0x200),[0x18]=len}; RESP read at gf_mem+0x40 (was wrongly +0x100 -> always read 0!);
    resp_buf passed = gf_mem_phys+0x40. In-kernel sets payload phys directly (no ion/modfd needed).
  - gf_ta_setkey uses gf_ta_send_io(2,109,256, keymaster_resp,256).
  - gf_ta_init runs the real GF_CMD sequence: setkey, DETECT_SENSOR(1000), DOWNLOAD_FW(1003),
    DOWNLOAD_CFG(1004), INIT(1001), INIT_FINISHED(1005), TEST_GET_VERSION(1037), logging each.
  - gcmd sysfs now "arg1[:len[:grp]]" for arbitrary testing.
  - FIXED use-after-free: gf_remove now device_remove_file(ginit/gcmd/gdump) (missing before -> repeated
    rmmod/insmod left stale sysfs -> dev_attr_store oops). gf_log_step null-guards gf_mem.
BLOCKER hit while testing: gfber app became -19 ENODEV (unloaded during reload churn); the driver assumes
  gfber is resident (gf_app_id) and does NOT load it. Must load gfber (+fpcber for keymaster) via the shim
  first, THEN goodix_fp. Shim+goodix_fp co-loaded caused gfber -19 (contention); plan = shim loads gfber,
  rmmod shim, insmod goodix_fp.
DEVICE HUNG (2026-10-09 ~07:00) on a qsee22 RAM-boot after a reboot-to-bootloader cycle: dropped off USB
  entirely (no enumeration, no fastboot, no net). NOT an SE/XPU hang (did not touch SE this session) —
  likely transient boot hang after the churn + earlier kernel oops. Needs MANUAL power-cycle -> installed r1.
CLEAN RUN RECIPE (when device back, RAM-boot qsee22, scp new goodix_fp.ko + qseecom_shim.ko):
  1. insmod qseecom_shim; python LOAD "gfber" (note id) + LOAD "fpcber"; rmmod qseecom_shim.
  2. insmod goodix_fp gf_app_id=<id> km_app_id=1.
  3. echo 1 > .../ginit ; read dmesg for the GF_CMD sequence statuses + TEST_GET_VERSION payload (=sensor
     version = proof of life).
TODO next build: make goodix_fp LOAD gfber itself (via qcom_scm_qseecom_load_image) so no shim needed.

### Finding M — driver dispatches correctly (separate payload buf); sensor DETECTED (2026-10-09)
Root cause of "status 0 for everything": the payload MUST be a physically SEPARATE tzmem buffer from the
cmd/resp buffer. The shim worked because it used h->aux (separate); the driver used gf_mem+0x200 (same
buffer) -> TA no-op'd. FIX: driver now allocs gf_pay (separate 0x800 tzmem), payload phys = gf_pay_phys at
[0x14]; whitelist args stay 0,0 (shim uses 0,0 too — not a whitelist issue). goodix_fp.ko rebuilt 07:17.
Clean run (gfber app3, km app1) now gives DIFFERENTIATED real responses + payload data:
  setkey (cmd2/a109)   -> status=1010 (consistent w/ shim; open_session ignores it; likely benign)
  DETECT_SENSOR(a1000) -> status=0   pay=00000000 000003e8 00000033 00000000   <-- SENSOR DETECTED
  DOWNLOAD_FW  (a1003) -> status=1070 pay=.. 0000042e(=1070 echo)
  DOWNLOAD_CFG (a1004) -> status=1070
  INIT         (a1001) -> status=0   pay=00000000 000003e8 00000033 00000000
  INIT_FINISHED(a1005) -> status=0   pay=00000000 00000001 00000009 00000000   <-- state changed
  TEST_GET_VERSION(a1037) -> 1070 ;  bogus a9999 -> 1070
Payload layout looks like {u32 r0=0, u32 cmd/arg echo, u32 0x33, u32 statusEcho}. [0x40] status and
payload[3] agree. 1070 (=GF_CMD_TEST_READ_FW in the map) is returned for DOWNLOAD_FW/CFG/GET_VERSION/bogus
-> likely "fw not loaded / not ready / needs input data or a precondition cmd". DETECT/INIT/INIT_FINISHED
succeed (0). gcmd sysfs = "arg1[:len[:grp]]" for probing without rebuild.
REMAINING: (1) correct init ORDER (reinit does DETECT->INIT->DOWNLOAD_CFG->INIT_FINISHED, no DOWNLOAD_FW);
(2) version read may need TEST_PRE_GET_VERSION(1036) before 1037; (3) DOWNLOAD_FW/CFG may need real fw/cfg
data as payload; (4) then CAMERA_CAPTURE(1021)/AUTHENTICATE(1010) + enroll. TA fully responsive.

### Finding N — gfber is STATEFUL and order-sensitive; can wedge to -22 (2026-10-09)
Results vary by state/order, NOT fixed per command:
  fresh ginit: DETECT_SENSOR=0, INIT=0, INIT_FINISHED=0.
  repeated gcmd run: DETECT_SENSOR=1062, INIT=0, DOWNLOAD_CFG=1070, then INIT_FINISHED=-22 (scm EINVAL),
  after which ALL commands return -22 (gfber session wedged until the app is reloaded).
=> gfber keeps session state; wrong order or repeating a step wedges it (-22). Must drive the EXACT HAL
   order once per fresh app load, and likely feed real input data to DOWNLOAD_FW/CFG. Payload shape seen:
   {r0=0, cmdOrChipEcho(=0x3e8 often), 0x33, statusEcho}. Need to RE gf_hal_download_fw/download_cfg to get
   the fw/cfg DATA + the precise call order, and gf_hal_get_fw_info/test_get_version for the version read.
STATUS: the hard breakthroughs are done (keymaster, correct ABI, TA dispatches + talks to sensor, DETECT
   SENSOR=0 on fresh init = sensor reachable). The remainder is stateful protocol RE (exact order + data +
   per-command state), best done from a fresh app each attempt. This is iterative, not a wall.

### Finding P — GF_ERROR table decoded; status reinterpretation (2026-10-09) **CORRECTS J/M/N/O**
Decoded the real GF_ERROR table (libgf_hal, separate from the GF_CMD table; reloc-resolved):
  1000 GF_ERROR_BASE, 1001 OUT_OF_MEMORY, 1002 OPEN_TA_FAILED, 1003 BAD_PARAMS,
  1005 REACH_FINGERS_UPLIMIT, 1010 GENERIC, 1017 HAL_IOCTL_FAILED,
  1062 SENSOR_NOT_AVAILABLE, 1070 UNKNOWN_CMD.
The gfber status at send_buf[0x40] is a GF_ERROR code. So:
  - setkey (cmd2/a109) -> 1010 = GF_ERROR_GENERIC (open_session ignores it; benign-ish).
  - DETECT_SENSOR -> 0 (sensor available) vs 1062 SENSOR_NOT_AVAILABLE (reflects real HW/power state).
  - DOWNLOAD_FW(a1003)/DOWNLOAD_CFG(a1004)/GET_VERSION(a1037)/bogus(a9999) -> 1070 UNKNOWN_CMD:
    the TA does NOT recognize those arg1 as group-1 sub-commands AS I SENT THEM. My "arg1 = GF_CMD number"
    mapping holds for 1000/1001/1005 (accepted) but NOT 1003/1004/1037. Need the real sub-cmd numbers/
    path for download/version (likely a different group or a HAL-side translation in invoke_command_ex).
RETRACT Finding O: download_fw/cfg pass a ZEROED 96-byte buffer (len=0x60) exactly like the HAL — they do
  NOT carry an OTP-assembled config. The "~10KB OTP/calibration + libhybris" scope was OVERSTATED. Minimal
  init may be just DETECT->INIT->INIT_FINISHED (all returned 0). invoke_command_ex uses cmd_grp=1,
  arg1=GF_CMD, payload=96B zeroed, len=0x60 via vtable [[0x3b000+0x860]+0xd0] (= gf_ca_invoke_command).
  My driver used len=256 (should be 0x60=96). TODO: full call-site table (grp/arg1/len/data) for all sites.
WEDGE: once gfber returns -22 (scm result=-19 ENODEV) it STAYS dead for all commands — the TA session is
  gone and the shim LOAD/UNLOAD can't revive it (UNLOAD is a no-op; LOAD returns a stale id but TZ has no
  live app). Only a TZ reset (reboot) clears it. So: run the init sequence exactly ONCE per fresh boot, in
  the right order (guessing/repeats wedge it). TODO: expose qcom_scm_qseecom_app_shutdown via the shim to
  force-unload+reload gfber without a reboot. Awaiting Fable's static analysis of the exact minimal order
  before the next clean on-device shot.
NOTE: "sensor DETECTED" (DETECT=0) is still UNVERIFIED as a real SPI touch — must run the vdd-off control
  (DISABLE_POWER 0x6708 / reset held); if DETECT still 0 with power off, the TA never touched HW.

### Finding Q — SENSOR TOUCH VERIFIED (power on/off control) + init core works (2026-10-09) **VERIFIED**
Tooling: shim UNLOAD now force-shuts-down the TA (qcom_scm_qseecom_app_shutdown; ioctl 0x9709, magic 0x97
NOT 'g') -> can reload a wedged gfber FRESH without a reboot (verified: shutdown app3, reload app9/12).
Integrated test (gf5.py): goodix_fp loaded for power/clock/reset via its ioctls (ENPWR 0x6707, ENCLK
0x40046705, RESET 0x6702, DISPWR 0x6708) + gfber driven via the shim modfd (correct transport,
separate dma_buf payload, len=0x60, grp=1). Fresh gfber each run via force-unload.
CONTROL RESULT (definitive proof of SPI touch):
  DETECT_SENSOR power-ON  -> status 0     (sensor available)
  DETECT_SENSOR power-OFF -> status 1062  (GF_ERROR_SENSOR_NOT_AVAILABLE)
  DETECT_SENSOR power-ON2 -> status 0     (reproducible)
=> The result TRACKS the vdd pin => the TA genuinely reads the sensor over SPI. "Sensor reached" is now
   VERIFIED (not the earlier unproven claim). SE/SPI path works end to end through the keyed TA.
INIT CORE (power on): setkey(cmd2/a109)=1010 GENERIC (ignored by HAL); DETECT=0; INIT(a1001)=0;
  INIT_FINISHED(a1005)=0 with state change (payload {0,1,9,...} vs {0,0x3e8,0x33,...}). Init core SUCCEEDS.
  GET_VERSION(a1037)=1070 UNKNOWN_CMD (version read is a different path/group — awaiting Fable).
Payload shape after DETECT/INIT: {r0=0, 0x3e8(=1000), 0x33(=51), statusEcho, 0x33, 0x33}; after
  INIT_FINISHED {0,1,9,...}. 0x33=51 recurring (sensor/chip field?).
STATUS: sensor verified reachable + init core works. Next: capture/enroll path (CAMERA_CAPTURE 1021,
  PRE_ENROLL 1006, ENROLL 1007, AUTHENTICATE 1010) and the version-read/UNKNOWN_CMD path from Fable.

### Finding R — full gfber protocol recipe (Fable 5.1 disasm of libgf_hal, 2026-10-09)
GROUP = send_buf[0x04]; arg1 forwarded UNCHANGED (no opcode table); each group implements its own arg1 set:
  grp1 main (invoke_command_ex @0x1a6f0, vtable [[0x3b860]+0xd0]=hal_milan_f_series_invoke_command @0x2d9cc)
  grp2 user/key (@0x1dc44, setkey arg109)   grp3 TEST (@0x23ab8, GET_VERSION/PRE_GET_VERSION)   grp4 dump
WHY 1070: DOWNLOAD_FW/CFG(1003/4) are NOT standalone grp1 cmds on Milan-F (folded into INIT(1001)+OTP; only
  reinit @0x1a3b0 / ESD use them) -> benign. GET_VERSION 1037 is grp3; I sent grp1 -> UNKNOWN_CMD.
hal_milan_f_series_invoke_command only checks len>=0x60 (else 1003 BAD_PARAMS) then forwards; TA decides arg1.
LEN matters: response copied back only `len` bytes (gf_ca_invoke_command @0x2674). Per-cmd minimum lengths:
  DETECT_SENSOR >=356, INIT >=168, GET_VERSION/PRE_GET_VERSION 568. Flat 256 TRUNCATES DETECT readback.
MINIMAL COLD INIT (after char-dev device_open/ENABLE_POWER/get_fw_info ioctl/reset + control_spi_clock):
  1. setkey      grp2 arg109  len256  payload=256B keymaster resp   (return ignored; 1010 benign)
  2. DETECT_SENSOR grp1 arg1000 len356 zeroed -> 260B sensor-info at payload+0x60; +0x64 = series (milan_f)
  3. INIT        grp1 arg1001 len168  payload[0x60]=fw_info[0], [0x84..0xa3]=32B OTP cache (zeros OK)
                 -> row/col at payload+0x64/+0x68
  4. INIT_FINISHED grp1 arg1005 len100 zeroed
  then device_enable: netlink thread + ENABLE_IRQ.
PROOF-OF-LIFE (real sensor data): grp3 arg1036 TEST_PRE_GET_VERSION len568 (MANDATORY first), then grp3
  arg1037 TEST_GET_VERSION len568 -> version arrays in the 568B payload at +0x60,+0xa0,+0xe0,+0x120.
  Alt: DETECT len356 -> inspect payload[0x60..0x163] (series + row/col). Nonzero = SPI proven.
CAPTURE/ENROLL/AUTH (grp1; results are IRQ-driven, NOT inline):
  CAMERA_CAPTURE 1021: 96B zeroed.   ENROLL 1007: len176, payload[0x60]=group_id, [0x69..0xb0]=HAT.
  AUTHENTICATE 1010: len120, payload[0x60]=op_id, [0x68]=8B gatekeeper challenge, [0x70]=screen flag.
  Flow: SEND enroll/auth -> arm capture (cmd 1021 -> device notify) -> finger IRQ -> kernel netlink ->
  irq handler (hal_milan_f_series_irq @0x2de48 / image_irq @0x2e808) sends GF_CMD_IRQ arg1016 grp1 with a
  ~0x36a20 (~218KB) image buffer to pull frame+match -> notify_auth_succeeded/failed + enroll_progress
  (fid/group/remaining). Image bytes live in that 218KB buffer.
Fable artifacts: scratchpad/{hal.asm,ca.ann,test_cmd.ann,milanf_irq.ann}.

### Finding S — FULL INIT + SENSOR FIRMWARE VERSION READ (2026-10-09) **MAJOR — sensor fully alive**
Ran Fable's recipe (gf6.py: goodix_fp power/clk/reset + shim modfd, per-cmd groups/lengths, fresh gfber):
  setkey    grp2/a109 len256 -> 1010 (benign)
  DETECT    grp1/a1000 len356 -> 0; info@payload+0x60=15 00 03 00 20 00 05 00 0101...; series@0x64 = 3 (Milan-F)
  INIT      grp1/a1001 len168 -> 0; row/col @0x64/@0x68 = 0x58/0x6c = 88 x 108  (sensor image array dims!)
  INIT_FIN  grp1/a1005 len100 -> 0
  PRE_GET_VER grp3/a1036 len568 -> 0
  GET_VERSION grp3/a1037 len568 -> 0; payload+0x60 ASCII:
     "Milan_v_3.01.11.02"  "Preprocess_v_1.01.01"  "<REDACTED device token>"  "<REDACTED device token>"
=> The TA read the REAL sensor firmware version + dimensions over SPI. The Goodix Milan-F is fully
   detected, initialized, and reporting. End-to-end chain VERIFIED: keymaster key -> gfber keyed ->
   power/clk/reset -> DETECT -> INIT -> INIT_FINISHED -> version read. This is undeniable proof of life.
Key correctness factors: grp3 for TEST cmds (version), per-cmd lengths (356/168/568; flat 256 truncated),
   payload in a SEPARATE tzmem buffer, fpcber resident for keymaster, fresh gfber via force-unload.
REMAINING to a usable reader: CAMERA_CAPTURE (1021) / ENROLL (1007) / AUTHENTICATE (1010) — IRQ-driven
   (see Finding R): arm capture, finger IRQ -> netlink -> irq handler sends GF_CMD_IRQ(1016) grp1 with a
   ~218KB image buffer -> frame+match -> notify. Then wire IRQ->netlink in the driver + libfprint/PAM.

### Finding T — FINGER TOUCH DETECTED (IRQ fires on contact) 2026-10-09 **physical sensing works**
After full init + ENABLE_IRQ (0x6703) + arm CAMERA_CAPTURE (grp1/1021/96B), monitored /proc/interrupts
irq 226 (msmgpio 121, goodix_fp) during a finger hold:
  no finger: flat (12047, then 12598 baseline)
  finger ON: +~19 IRQ/sec steadily, delta +356 over 20s; flat again when lifted.
=> The sensor physically detects the finger and raises the GPIO IRQ while touched. CAMERA_CAPTURE arms
   finger-detect. (Earlier "no IRQ" was a missed tap window, not a failure.) So: power/clk/reset + keyed TA
   + init + arm => the sensor senses touch end-to-end. Only the FRAME PULL remains.
NEXT: pull the frame. Each IRQ -> HAL sends GF_CMD_IRQ(1016) grp1 with the image buffer (~218KB per Fable).
   BLOCKER: my shim bounces the dma_buf through a tzmem aux sized = SB (~4KB); a raw 88x108 frame (~9-19KB)
   and the 218KB HAL buffer both exceed it. FIX NEEDED: shim passes a CONTIGUOUS dma-buf's real phys
   (alloc from /dev/dma_heap/default_cma_region) directly into the cmd (no bounce), like the HAL's ION path.
   Awaiting Fable for the exact GF_CMD_IRQ frame-read sequence + minimum buffer size.

### Finding U — REAL SENSOR FRAMES CAPTURED on finger touch (2026-10-09) **capture works**
Implemented IRQ-driven capture in goodix_fp: gf_img = alloc_image(0x37000) (tzmem pool too small for 225KB;
alloc_image/dma works); gf_ta_img() sends GF_CMD_IRQ(1016) with gf_img phys directly (no shim bounce).
Threaded gf_irq pulls 1016 on each GPIO IRQ when armed; auto-stops when the frame region has pixels.
Flow: ginit -> autocap=1 (sends grp3/1067 TEST_REAL_TIME_DATA + arms) -> finger touch -> GPIO IRQ ->
  gf_pull_irq -> status 0, **irq_type=0x80 (IMAGE bit7)**, op=39, frame region fully populated.
Buffer layout confirmed (op39): base=irq_buf+0xb118; four u16 88x108 (19008B) frame slots at +0x60/+0x73e0/
  +0xe760/+0x15ae0 = file offsets 0xb178/0x124f8/0x19878/0x20bf8:
    slot0 @0xb178  = FLAT 0x2000 (dark/baseline reference)
    slot1 @0x124f8 = raw frame, min8281 max9593 stddev210 (real pixel variation)
    slot2 @0x19878 = processed, min0 max2498 stddev389
    slot3 @0x20bf8 = min1902 max4085 stddev120
=> VERIFIED: the sensor produces real pixel frames on touch, read end-to-end through the keyed TA.
CAVEAT: raw frames are dominated by row-wise FIXED-PATTERN NOISE (2-row odd/even gain). After row+col FPN
  removal, no clear fingerprint RIDGE flow emerged (residual ~noise) — likely weak/off-center contact and/or
  these op39 TEST frames are pre-processing. A clean ridge image / match comes from the normal acquire path
  (image_irq ops 0/1/2/34/35) armed via AUTHENTICATE(1010)/ENROLL(1007), where the TA does exposure+
  processing internally and yields a template/match (not necessarily a viewable raw image).
Driver sysfs: ginit, gcmd "arg[:len[:grp]]", capture (one 1016 pull), autocap (arm+IRQ-capture), frame
  (bin attr, dumps gf_img 0x36a20). Tools: gf6/7/8.py. Frame data saved: fingerprint/imgbuf.raw.
NEXT: for a real unlock, drive ENROLL/AUTHENTICATE (needs a gatekeeper HAT/challenge — PIN/password TA),
  then libfprint/PAM. For a viewable image: firmer centered contact + average frames / proper FPN+baseline
  calibration, or the processed-acquire ops.

### Finding V — enroll/auth paths RE'd (TEST path needs NO HAT); prettier-image = calibration, not math (2026-10-09)
Offline session (device away, no reboots). Disassembled the HAL enroll/auth call sites + analysed imgbuf.raw.

ENROLL/AUTH COMMAND MAP (grp = send_buf[0x04], arg1 = sub-cmd, len = response copy-back):
  * NORMAL path (needs a gatekeeper HAT):
      PRE_ENROLL   grp1/1006 len104 (malloc 0x68 zeroed).
      ENROLL       grp1/1007 len176 (malloc 0xb0): payload[0x60]=group_id (w2), [0x68]=0 byte,
                   [0x69..0xb0]=the 69-byte hw_auth_token (HAL just COPIES it in via ldr/stur q-regs at
                   +0x69/+0x79/+0x89/+0x99/+0xa6; gf_hal_common_enroll @0x1c2f8). The HAL does NOT verify
                   the HAT — if anything verifies it, gfber does (TA-side, unseen). "GF_ERROR_INVALID_HAT_
                   VERSION" + "challenge is NULL" strings exist => at least a version/challenge check lives
                   somewhere. "gatekeeper required" remains UNPROVEN (advisor): a zero-HAT error tells little.
      AUTHENTICATE grp1/1010 len120: [0x60]=op_id, [0x68]=8B challenge, [0x70]=screen flag.
  * TEST path (NO HAT, the FRR/FAR factory route — our offline-of-gatekeeper lever):
      TEST_ENROLL  grp3/1060 len96  (gf_hal_test_invoke_command_ex @0x23ab8: malloc 0x60 zeroed, w0=3
                   grp3, w3=0x60; hal_test_enroll @0x23bbc fires 1060 then notify_acquired(1021)).
      TEST_AUTH    grp3/1061 len120 (hal_test_authenticate @0x23c48: malloc 0x78, [0x60]=op_id(w2),
                   [0x68]=challenge(x1, 8B), w0=3 grp3). NO HAT parameter anywhere.
  CAUTION (advisor): the TEST path is a DEV HOOK, not a proven unlock — it answers "does the TA enroll+
  match on this sensor", not "does a real unlock work". Its results may come via gf_hal_notify_test_
  enrollment_progress (0x23f5c) and its template may not be what grp1/1010 AUTHENTICATE uses or persist.
RESULT FIELDS are IRQ-driven, not inline: after arming, each finger IRQ -> GF_CMD_IRQ(1016) grp1 pull;
  hal_milan_f_series_irq (@0x2de48) is a bit-test dispatcher on irq_type (bit7=0x80 IMAGE confirmed) and
  reads enroll-remaining / match-fid / result from irq_buf offsets then calls the notify fns. The exact
  offsets are NOT yet pinned (big 0x900-byte handler); the driver's pull-trace (on-change ring + per-state
  header snaps) reveals them from ONE touch session (advisor's plan).
ARMING (resolved by disasm): gf_hal_common_enroll (success @0x1c4bc) and gf_hal_common_authenticate
  (@0x1c728) do NOT send a CAMERA_CAPTURE(1021) command after ENROLL(1007)/AUTH(1010) — they store
  {1,0x3fd=1021} and call a NOTIFY callback (via [0x3b868][0], NOT the TA-invoke vtable [0x3b860]+0xd0).
  So "1021" in that path is the ACQUIRED-INFO notify code, not a TA command; the enroll/auth command
  itself arms finger-detect. (Separately, grp1/1021 CAMERA_CAPTURE as a standalone command DID arm the
  IRQ in the gf7/gf8 capture flow, Finding T.) => the probe's arm_check only REPORTS whether IRQs climbed;
  it must NOT auto-send 1021 after the enroll/auth op (different op, would clobber). If arming fails, the
  deliberate next experiment is CAMERA_CAPTURE(1021) BEFORE arming.

PRETTIER IMAGE = CALIBRATION, NOT OFFLINE MATH (decided this session, geometry CORRECTED):
  GEOMETRY FIX (advisor caught this): the op39 slots are 0x7380=29568B=14784 u16 apart; I had under-read
  each to 19008B and rendered at width 88 -> a DIAGONAL SHEAR (the classic wrong-stride artifact; the
  earlier "diagonal dash grid / bad-point pattern" was NOT real, it was the shear). Autocorrelation of
  slot2 has its clear peak at lag 108 (harmonic at 216; value normalised to the lag-60..260 max so the
  "1.000" is by construction) => true row stride = 108. Frame = 108 wide x 88 tall (INIT col/row =
  0x6c/0x58 = 108/88); only the first 9504 of the 14784 u16 are image, the rest padding/aux.
  Re-rendered at W=108 (scratchpad c_*.png): shear gone, frame axis-aligned — strong column FPN (odd/even
  column gain) + row FPN + a smooth low-frequency central brightness lobe.
  RIDGE TEST (done properly this time): col+row FPN removal, then Difference-of-Gaussians band-pass
  (sigma 1.2 - sigma 5.0, keeps ~4-14px period) on ALL THREE slots (scratchpad bp_s1/2/3.png) + a radial
  power profile. Result: band-passed images = speckle noise + faint residual stripe, NO ridge flow; the
  radial power peaks at k=3-4 (27-36px = the low-freq lobe) and DECAYS monotonically through the ridge
  band (k=9-21 = 5-12px period) to the floor — NO ridge annulus.
  => CONCLUSION: no fingerprint ridges are recoverable from THIS capture by offline math. CAUSE UNRESOLVED
  — three candidates, not yet separable: (a) light/off-center contact in this grab, (b) no calibration
  base (s0 is a constant 8192, not a real finger-off frame; a static gain/vignetting profile would also
  produce the central lobe — so the lobe is NOT proof the finger was imaged; the finger evidence is the
  IRQ rate in Finding T), (c) op39 is a raw diagnostic stream that is pre-processing. Next data to separate
  them: a firm centered press, a real finger-off base via OPERATION_TEST_BIO_CALIBRATION / FINGER_BASE /
  HBD_CALIBRATION (grp3 arg1 inlined in a test dispatcher, TBD), and/or the normal ENROLL/AUTH acquire
  path where the TA preprocesses internally (yields a template/match, not necessarily a viewable raw).

DRIVER (dist/qsee22/goodix_fp.ko, 577032, rebuilt clean 2026-10-09): turned into a FLEXIBLE PROBE (advisor)
  rather than a blind state machine, since nobody can touch the sensor to validate one this round:
  * gf->ta_lock serialises gf_mem/gf_pay/gf_img across the threaded IRQ handler + every sysfs store
    (was an unlocked race).
  * cap_mode {NONE,TEST,ENROLL,AUTH}: TEST frame grab auto-stops on pixels; ENROLL/AUTH STAY armed across
    presses (the TA accumulates/matches over several touches).
  * new sysfs: gpay ("OFF HEX" stages payload bytes at an offset -> group_id/op_id/challenge/HAT for the
    next gcmd), enroll ("1"=TEST grp3/1060, "7"=real grp1/1007 with staged HAT), authenticate
    ("op:lo:hi"=TEST grp3/1061, "r:op:lo:hi"=real grp1/1010), trace (ring 96 of GF_CMD_IRQ pulls recorded
    ON CHANGE: irq_type/op/step/status/irq_buf[0x60..0x9f] — survives a multi-second press at ~19 IRQ/s),
    snaps (bin attr: a 0x200B header snapshot per distinct irq_type/op/step — result field may be anywhere
    in the header). gcmd now uses the staged gpay payload when present.
ON-DEVICE SCRIPTS staged (fingerprint/on-device/): gfload.py (force-unload stale gfber, load fresh +
  fpcber, print GFBER_ID; both stay resident — shim close() does NOT shut down, only the UNLOAD ioctl
  does), enroll-probe.sh (step4 NO-TOUCH gating probe of 1060/1061/1006/1007/1010 reading status only;
  step5/6 TOUCH test-enroll/auth reading trace; reset_gfber no-reboot recovery). NEVER co-load shim+
  goodix_fp (gfber -19). NO reboots/fastboot-boot while Yaron is away (hang needs manual power-cycle).
### Finding W — enroll/verify loop RE'd + HAT gate confirmed on-device; Linux path avoids gatekeeper (2026-10-13)
On-device RAM-boot (qsee22), full init solid (DETECT/INIT/INIT_FINISHED=0, version=0). Drove enroll/auth by hand + RE'd the HAL IRQ handler. Results:

IRQ-LOOP MECHANISM (hal_milan_f_series_irq @0x2de48, from milanf_irq.ann): the whole per-touch loop is
  driven by GF_CMD_IRQ — EVERY gf_hal_invoke_command in the handler uses w0=0x3f8=1016. It pulls the IRQ
  buffer (1016), reads irq_type/op, dispatches (nav via send_nav_event / key via send_key_event / IMAGE via
  hal_milan_f_series_image_irq @0x2e808), and RE-ARMS the next touch with gf_hal_enable_irq (the Linux GPIO
  IRQ) — NOT a separate TA arm command. The TA keeps detect alive during a CONTINUOUS operation.
  gf_hal_common_camera_capture (0x1d76c) = just invoke_command_ex(1021) (grp1 CAMERA_CAPTURE).

HAT GATE (no-touch probe on fresh init, zeroed payloads):
  PRE_ENROLL   grp1/1006 len104 -> status 0       (dispatches)
  ENROLL       grp1/1007 len176 -> status 1056    (zeroed HAT rejected; 1056 ~ GF_ERROR_INVALID_HAT_VERSION
                                                    — the enroll genuinely VERIFIES the 69-byte gatekeeper HAT)
  AUTHENTICATE grp1/1010 len120 -> status 0       (zeroed op_id/challenge ACCEPTED — auth needs NO HAT)
=> ENROLL(1007) requires a valid gatekeeper HAT (a gatekeeper TA + PIN would mint it). AUTHENTICATE(1010)
   needs no HAT, only a stored template.

WHY TODAY'S MANUAL ENROLL FAILED: TEST_ENROLL(grp3/1060) is SINGLE-SHOT — it armed exactly one acquire
  (one op=34 IRQ) then did not re-detect; my probe pulled the frame but never re-issued 1060, so the loop
  died, and the churn drifted the sensor to 1062 SENSOR_NOT_AVAILABLE. The continuous enroll is the NORMAL
  path (1007), which the TA keeps detecting for — but it needs the HAT. Capture itself is fine: the proven
  grp3/1067 path still gives a full op=39/irq_type=0x80 frame (nz=9504) on one touch this session.

LINUX INTEGRATION (the decision): fprintd/libfprint have NO HAT/gatekeeper concept — that is an Android HIDL
  requirement the TA enforces. So the clean Linux route AVOIDS the gatekeeper entirely:
    enroll  = TEST_ENROLL(grp3/1060), re-issued per touch (no HAT), pull frames via GF_CMD_IRQ(1016),
              read progress, until the template is complete;
    verify  = AUTHENTICATE(grp1/1010) (no HAT), pull via 1016, read match result.
  This is exactly a libfprint MATCH-ON-CHIP driver's enroll/verify loop (model on goodixmoc). GNOME Settings
  enroll UI + pam_fprintd unlock then come for free.
  OPEN QUESTION (next touch session): does TEST_ENROLL(1060), re-issued per touch to completion, build a
  template that AUTHENTICATE(1010) actually MATCHES? If yes -> no gatekeeper needed, write the libfprint
  driver. If no -> must mint a HAT via the gatekeeper TA (find+RE it like keymaster/fpcber) for 1007.
  DRIVER TODO: an enroll mode that RE-ISSUES 1060 after each acquire + services GF_CMD_IRQ(1016) properly
  (today's single-arm probe can't loop). Or drive the loop from userspace (the libfprint driver's job).

### Finding X — corrections (advisor) + UNTRUSTED enroll/auth is the no-gatekeeper path + HAL IRQ loop exact (2026-10-13)
CORRECTIONS to Finding W (several claims were overstated):
- 1060/1061 are NOT FRR/FAR-record. gf_cmd_map: **1060 = GF_CMD_TEST_UNTRUSTED_ENROLL, 1061 =
  GF_CMD_TEST_UNTRUSTED_AUTHENTICATE** — enroll/match deliberately WITHOUT the trusted gatekeeper HAT.
  This is the intended no-gatekeeper path (exactly what Linux/libfprint needs). NOT a throwaway test.
- **1056 (the ENROLL-zeroed-HAT status) is UNDECODED.** I twice conflated the GF_CMD and GF_ERROR tables;
  gf_cmd_map 1056=TEST_RESET_FWCFG is a DIFFERENT namespace. The GF_ERROR meaning of status 1056 is
  unknown (candidates: INVALID_CHALLENGE / INVALID_HAT_VERSION / a state error). So "1007 verifies the HAT"
  is UNPROVEN — it is only "1007 with a zeroed payload (after a pre_enroll) returns 1056". The crafted-HAT
  probe (version + real pre_enroll challenge + zero HMAC) is still the way to learn which check it is, but
  it is now LOW priority because 1060 (untrusted) is the real Linux path.
- "TEST enroll is single-shot" was one-sample and is downgraded to a hypothesis (see BLOCKER below).

HAL IRQ LOOP — exact buffer (hal_milan_f_series_irq @0x2de48, from milanf_irq.ann 2df40-2e010):
  seeds image buffer: [0x367e1]=0x02000000, [0x367e5]=0 (8B), [0x36810]=0x200, [0x36a18]=1 (step);
  calls gf_hal_invoke_command(cmd=0x3f8=1016, buf, len=0x36a20) ONCE (not a step-resend loop);
  on success reads [0x36a14] (-> g_spi_speed) and dispatches on irq_type=[0x60]; the ONLY re-arm is
  gf_hal_enable_irq (the Linux GPIO IRQ) — there is NO per-touch TA command (no camera_capture re-issue;
  the invoke_command_ex @2e7e4 is in hal_key_long_pressed_timer_thread, cmd 1075, unrelated). The TA keeps
  the sensor in finger-detect internally during a continuous operation. => my driver's gf_pull_irq buffer
  already matches; the multi-resend loop is unnecessary but harmless.

BLOCKER (enroll loop) — HYPOTHESES, not settled: UNTRUSTED_ENROLL(1060) returned status 0 + produced
  exactly ONE acquire IRQ (op=34, irq_type=0x2) from ~10 taps, then DETECT drifted to 1062. The capture
  path (1067) gives a clean single op=39/0x80 frame (nz=9504) per touch. So the sensor+pull work; what
  fails is CONTINUOUS enroll detect. Candidates: (a) 1060 does not hold continuous detect (needs a
  per-acquire re-issue the trusted 1007 path gets internally), (b) the sensor IRQ line stays asserted after
  the pull (edge-triggered RISING -> no new edge until it de-asserts), (c) contact/timing on the taps.
  DECISIVE next test (one finger session): reset gfber fresh, ginit, 1060, then 5 SLOW fully-lifted taps
  while watching /proc/interrupts per tap — IRQ rises per tap => detect works (earlier was contact/timing);
  flat => enroll mode isn't holding detect (try re-issuing 1060 or 1021 per acquire, or crafted-HAT 1007).

THREE FRONTIERS status: (1) enroll/auth unlock = path FOUND (UNTRUSTED 1060/1061, no HAT); blocker =
  continuous enroll detect (above). (2) libfprint/PAM = follows (1); architecture = a match-on-chip driver
  over the TA (userspace over the shim, mirroring the vendor HAL; GNOME enroll UI + pam_fprintd unlock free).
  (3) viewable image = calibration: op39 capture works but FPN-dominated with no base; need the calibration/
  base command (OPERATION_TEST_BIO_CALIBRATION / FINGER_BASE / HBD_CALIBRATION; grp3 arg# still TBD) to build
  a finger-off base, then op39-minus-base. Repo: github.com/yarons/beryllium_fpc (renamed from _mainline).

### Finding Y — HAT HMAC IS verified (1056=challenge, 1057=HMAC); enroll needs gatekeeper OR host-driven untrusted loop (2026-10-13)
Crafted-HAT probe on-device (no finger), fresh gfber+ginit+PRE_ENROLL (challenge read from gdump @0x60 =
  88 8e 15 b5 42 d7 95 68). ENROLL(grp1/1007 len176) via gpay-staged payload:
  zeroed HAT                          -> status 1056
  HAT.challenge=real, HMAC=0 (@0x6a)  -> status 1057   (STATUS CHANGED)
=> the HAT checks are SEQUENTIAL: challenge first (zeroed -> 1056), then HMAC (zero HMAC -> 1057). So the TA
   GENUINELY VERIFIES the HAT HMAC — the trusted 1007 enroll requires a REAL gatekeeper-signed token and
   CANNOT be forged with a zero HMAC. (Resolves Finding W/X: "1007 verifies the HAT" is now PROVEN; 1056 =
   challenge-class error, 1057 = HMAC-class error — both are GF_ERROR codes, decoded empirically not by table.)
UNTRUSTED ENROLL (1060) re-confirmed: 5 SLOW fully-lifted taps on a fresh gfber -> exactly ONE acquire
  (op=34), IRQ 32->33. So 1060 does NOT hold continuous detect (not contact/timing). It fires one acquire
  per issue; a loop must RE-ISSUE per touch (mechanism TBD: re-issue 1060? a continue cmd?).

TWO PATHS TO A WORKING ENROLL (decision point):
  A. GATEKEEPER HAT (trusted, continuous): find+load the Qualcomm "gatekeeper" TA (like keymaster/fpcber),
     RE its enroll/verify-password -> HAT mint API, mint a HAT bound to a PIN, feed to ENROLL(1007). TA then
     holds continuous detect, enroll completes, template stored. AUTHENTICATE(1010) matches (no HAT). Proper,
     PIN-bound, more work. (Note: Linux fprintd has no gatekeeper concept, so the libfprint driver would mint
     the HAT internally via the gatekeeper TA.)
  B. UNTRUSTED host-driven loop (no gatekeeper): drive 1060 in a host loop (issue 1060 -> wait IRQ -> pull
     1016 -> read progress -> re-issue to re-arm) to completion, then AUTHENTICATE(1010) (no HAT). Cleaner for
     Linux IF the per-acquire re-arm works. NEXT TEST (1 touch): after the one acquire, re-issue 1060 and tap
     -> does a 2nd acquire fire? yes => path B works, build the loop; no => try 1021/continue, else path A.
Capture (1067) still gives a clean op39/0x80 full frame per touch (the image path is independent).

### Finding Z — untrusted ops are ONE-SHOT frame acquires (no continuous op); enroll needs the gatekeeper TA, which is NOT on the device (2026-10-13) **SESSION VERDICT**
Exhaustive on-device testing of the untrusted path:
  - Fresh ginit arms exactly ONE finger-detect cycle. The FIRST operation command after ginit + the next tap
    yields ONE acquire: UNTRUSTED_ENROLL(1060)->op=34, UNTRUSTED_AUTH(1061)->op=35, capture(1067)->op=39.
  - After that one acquire, the sensor does NOT re-detect: re-issuing 1060 then tapping = NO IRQ; a 2nd/3rd/…
    tap = NO IRQ; 5 slow fully-lifted taps = still ONE IRQ. Re-issuing the command does not re-arm.
  - Auth armed after a fresh ginit DID produce op=35 (a match-acquire), but only one frame, no match verdict in
    the trace words (w[0x60..0x9f] mostly 0); the verdict would come from the continuous op's later steps.
  => The untrusted/test commands produce single one-shot frame acquires, NOT the continuous multi-frame
     accumulate(enroll)/match(auth) operation. A real enroll (accumulate N frames + commit a template) and a
     real match verdict require the TA to HOLD detect across touches — the TRUSTED continuous path (1007/1010).
  => ENROLL(1007) requires a real HMAC-signed gatekeeper HAT (Finding Y: 1056 challenge -> 1057 HMAC, both
     verified; zero HMAC rejected). So a WORKING enroll NEEDS a gatekeeper-minted HAT. No no-gatekeeper shortcut.
GATEKEEPER TA AVAILABILITY: the pmOS firmware (/usr/lib/firmware/qsee/) ships ONLY fpcber, gfber, cmnlib,
  cmnlib64 — NO gatekeeper trustlet (and no keymaster image; keymaster64 is bootloader-resident app_id=1).
  So Path A needs the Qualcomm "gatekeeper" TA extracted from the STOCK MIUI firmware (vendor/firmware or
  /firmware/image on stock), added to /usr/lib/firmware/qsee/, then: load it -> RE its verify-password/enroll
  -> HAT-mint API (like keymaster/fpcber) -> mint a HAT bound to a PIN -> feed to trusted ENROLL(1007) ->
  continuous enroll -> template -> AUTHENTICATE(1010, no HAT) matches. Open risk: the gatekeeper<->gfber shared
  HMAC key must be derivable on pmOS (same class of question as the keymaster fpcber-precondition; may just work).

THREE-FRONTIER STATUS (end 2026-10-13):
  1) enroll/auth unlock: BLOCKED on the gatekeeper TA (not on device; extract from stock MIUI). This is THE path.
  2) libfprint/PAM: blocked behind (1); the libfprint MOC driver would load gatekeeper+mint HAT internally.
  3) viewable image: INDEPENDENT of gatekeeper — capture works (op39 full frame/touch); needs a calibration
     base (OPERATION_TEST_BIO_CALIBRATION / FINGER_BASE / HBD_CALIBRATION, grp3 arg# TBD) + op39-minus-base.
     This is the one frontier pursuable now without the gatekeeper blob.
Device left RAM-booted (qsee22, poco-usb); power-cycle -> installed r1, nothing flashed.

### Finding AA — gatekeeper IS the keymaster TA (resident); HAT mintable on-device, NO blob needed (2026-10-13) **PATH A UNBLOCKED**
The pmOS firmware has no gatekeeper trustlet, but gatekeeper does NOT need one: the vendor gatekeeper HAL
(android.hardware.gatekeeper@1.0-impl-qti.so, pulled to scratchpad/gk/) implements enroll/verify by sending
commands to the KEYMASTER TA via keymasterutils::KeymasterUtils::send_cmd (links libkeymasterdeviceutils.so).
Keymaster is app_id=1, bootloader-resident (dedicated keymaster_a/b partitions) — the SAME TA we already call
for the FP key (0x205). Disasm of GatekeeperHalDevice::verify @0x33b0 / ::enroll @0x3014 (objdump):
  cmd id = csel on security_level (field [x21+0x10]): ==2 (StrongBox) -> 0x15xx else (TEE) -> 0x10xx.
  **GK_ENROLL = 0x1001 (TEE) / 0x1501 (SB);  GK_VERIFY = 0x1002 (TEE) / 0x1502 (SB).** Our device = TEE.
  verify request (80B buffer built via KeymasterBuffer::append_to_buf): [0x00]=cmd_id(0x1002), [0x04]=uid,
  [0x08]=challenge(u64), then offset/length pairs at [0x10]+ for the appended {enrolled_password_handle,
  provided_password}; data blob appended after the header (standard QTEE km serialization). verify output =
  the 69B hw_auth_token (HAT), HMAC-signed, challenge-bound. enroll output = the password_handle.
Signatures: GatekeeperHalDevice::enroll(uid, curHandle,len, curPw,len, desiredPw,len, ->outHandle,->len);
  ::verify(uid, challenge, enrolledHandle,len, providedPw,len, ->outHAT,->len, ->reenroll).
PATH A (now concrete, mostly NO-FINGER): keymaster(app1) cmd 0x1001 enroll(PIN) -> password_handle; then
  cmd 0x1002 verify(uid, fp_challenge from gfber PRE_ENROLL(1006), handle, PIN) -> HAT; feed HAT into gfber
  ENROLL(1007) -> should clear the challenge(1056)+HMAC(1057) checks -> trusted continuous enroll (TA holds
  detect) -> template; AUTHENTICATE(1010, no HAT) matches. Only the enroll/auth frame-accumulation needs
  touches; the HAT mint is no-finger.
TODO to validate: (1) RE the exact append_to_buf wire format (offset/length pairs, blob order) for enroll +
  verify; (2) build the two keymaster calls (extend the driver's keymaster path, or via the shim+python like
  kmtest2.py); (3) mint a HAT (no finger) and feed gfber 1007 — if 1057 clears, Path A is proven; (4) then the
  continuous enroll with touches. RISK: keymaster's gatekeeper HMAC key may need provisioning on pmOS (same
  class as the fpcber precondition for 0x205) — unknown until tested. Vendor libs in scratchpad/gk/ (NOT repo).

### Finding BB — HAT-mint harness built; keymaster dispatches gatekeeper cmds but returns -30 (2026-10-13)
Built scratchpad/gkmint.py (over the /dev/qseecom shim): loads keymaster64 (app 1), sends GK_ENROLL(0x1001)
then GK_VERIFY(0x1002) with the RE'd 32B-header request. Transport CONFIRMED correct: KeymasterUtils::send_cmd
= plain QSEECom_send_cmd (disasm, 12B wrapper), and the shim SMC shows svc=0 cmd=1 status=0 result=0 (the TA
RAN and returned) — so the keymaster TA genuinely dispatches the gatekeeper command. BUT it returns
  resp[0] = 0xffffffe2 = -30 = KM_ERROR_VERIFICATION_FAILED   (for BOTH enroll and verify)
on every variant tried (preconditions resident; null vs 0x20 current-pw offsets). For a first-time ENROLL
there is nothing to verify, so -30 is NOT about the supplied password — it is the keymaster/gatekeeper
INTERNAL key check failing. Prime hypothesis: the gatekeeper root/HMAC key is not provisioned on pmOS (the
bootloader/keystore normally sets it at boot; same flavour as the keymaster-ROT story and the FP-key 0x205
fpcber-precondition). Secondary: a still-wrong enroll serialization (the uid/field order — enroll writes
[0]=cmd,[4]=w26,[8..]=3x{off,len}; w26 identity unconfirmed; uid may be a u64 SID).
FORMAT CONFIRMED CORRECT (full enroll disasm trace, GatekeeperHalDevice::enroll @0x3014): for a first-time
enroll (no current pw) the request is exactly [0x00]=cmd(0x1001), [0x04]=uid, [0x08..0x17]=0 (curHandle+curPw
off/len all zero, via the 327c "stp xzr,xzr" path), [0x18]=desiredPw_off(=0x20 after the 32B header),
[0x1c]=desiredPwLen, PIN at 0x20 — which is EXACTLY what gkmint.py sends. So -30 is NOT a format bug; it is a
keymaster gatekeeper STATE/key issue. And -30 = KM_ERROR_VERIFICATION_FAILED is NOT the "not configured" code
(that is -75), so keymaster configure (cmd 0x116, found in libqtikeymaster4.so KeymasterHalDevice::configure,
sets os_version/patchlevel via a serialized key_param_set) is UNLIKELY to fix it.
HONEST WALL: the keymaster gatekeeper refuses enroll with VERIFICATION_FAILED even with a correct request. On
Qualcomm the gatekeeper handle is HMAC(password, salt, hw_derived_key) — the key is hardware-derived (not
per-boot-provisioned), so a first enroll "should" just succeed; VERIFICATION_FAILED on enroll is anomalous.
UID/PW SWEEP: uid {0,1,1000,10000,100000,0xdeadbeef} x pinlen {4,16} -> ALL -30 (input-independent => the
gatekeeper path fails before reading params = a STATE/provisioning issue, not format).
CONFIGURE LONG-SHOT TESTED + EXHAUSTED (gkconfig.py): keymaster configure = cmd 0x116, req [0]=0x116
[4]=params_off(0xc) [8]=count, params = 12B each {tag(u32), value(u32), pad} (RE'd from params_serialize:
append is always w2=0xc; type=(tag>>28)^8 indexes a jump table; UINT->u32). With the correct 12B/param format
the length error cleared (-21 INVALID_INPUT_LENGTH -> -38), but configure returns -38 for EVERY os_version/
patchlevel value (value-independent — likely already-configured / unsupported-via-this-path), and gatekeeper
ENROLL stays -30 after every configure attempt. So configure is NOT the gate.
FINAL (2026-10-13): the fingerprint UNLOCK is walled at the keymaster gatekeeper on pmOS. Both enroll routes
dead: untrusted(1060) one-shot/no-accumulate (Finding Z); trusted(1007) needs a gatekeeper HAT that keymaster
REFUSES to mint (-30, input-independent; correct request format confirmed by disasm; configure doesn't help).
Transport + command IDs (GK_ENROLL 0x1001 / VERIFY 0x1002 / configure 0x116) + request formats all RE'd and the
TA dispatches — the TA itself refuses. A REAL unlock needs a bootloader/keystore-level fix to the keymaster
gatekeeper state (beyond Linux userspace). WHAT WORKS: the reader is fully alive to frame CAPTURE (power/clk/
reset, keymaster FP key via fpcber, gfber init, firmware version, op39 frame on touch). Tools gkmint/gksweep/
gkconfig.py + vendor libs in scratchpad/gk/. Device left RAM-booted (shim loaded, goodix_fp unloaded);
power-cycle -> installed r1.

NEXT (needs Yaron+device, when back): run step4 no-touch probe — does TEST enroll/auth gate before touch?
  does grp1/1007 with a zeroed HAT return INVALID_HAT (=> gatekeeper needed) or dispatch? Then step5/6
  touch enroll+auth and read the trace to pin the enroll-remaining / match-fid offsets. THEN decide:
  TEST-path enroll+match demo vs wiring a real gatekeeper HAT (PIN/password TA) for grp1/1007+1010, then
  libfprint/PAM. For a viewable image: find the calibration/base grp3 cmd and capture a finger-off base
  first. Also pending (Yaron): publish the whole fingerprint RE to GitHub (agreed to do together later).

### Finding O [RETRACTED — see P] full init needs the Milan-F runtime config (OTP+calibration), not a static blob (2026-10-09)
gf_hal_download_fw/cfg are thin (25 insns) -> just send the DOWNLOAD cmd; the DATA comes from a global
`g_hal_config` assembled at runtime from the sensor OTP (hal_milan_f_information_OTP) + calibration inside
gf_hal_milan_f_series_function_customize (~10KB). So DOWNLOAD_CFG returning 1070 with a zero payload is
expected — it needs the assembled config. Completing init to the point of CAMERA_CAPTURE requires
replicating that whole Milan-F bring-up (OTP read, config assembly, calibration, nav/timer setup).
STRATEGIC: given the chip bring-up complexity, running the REAL vendor HAL (fingerprint.goodix.so +
libgf_hal/libgf_ca) under libhybris on TOP of the working qseecom shim is likely MORE practical than
reimplementing the init in-kernel/python — the HAL already contains all the OTP/config/calibration logic
and just needs: /dev/qseecom (shim, works), /dev/goodix_fp ioctls (driver, works), /dev/ion->dma_heap shim,
and keymaster (works, with fpcber resident). The shim's send_modfd already matches what libgf_ca calls.
Decision point for Yaron: (A) continue reimplementing the Milan-F init natively (long), or (B) pivot to
libhybris to run the stock HAL over the working transport (also substantial but reuses vendor init).

OVERALL HONEST STATUS (end 2026-10-08): SOLVED today = keymaster get-key (fpcber-resident precondition),
   killed the SE/Linux-MMIO dead-end, proved sensor HW alive (IRQs+clock), identified the real gfber ABI.
   NOT solved = any real gfber command (wrong ABI used so far). Remaining path is a defined but non-trivial
   send_modfd replication, then the full init/capture/enroll sequence, then libfprint/PAM. Not close to a
   working reader; but the blockers are now concrete and ordered, not mysterious.
