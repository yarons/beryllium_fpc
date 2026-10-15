#!/bin/bash
# Poco F1 Goodix FP — enroll / authenticate probe (run from the mac, over ssh).
# Device = poco / poco-usb. Needs the NEW goodix_fp.ko (enroll/authenticate/trace/
# gpay sysfs) + qseecom_shim.ko from dist/qsee22.
#
# SAFETY / ORDER OF OPERATIONS
#  * step1_ramboot power-cycles into the bootloader and RAM-boots qsee22. Only run
#    it with YARON PRESENT: a boot hang needs a manual power-cycle (nobody-home =
#    stuck). Never insmod spi-geni / probe the SE (SoC hang, Finding C).
#  * shim and goodix_fp are NEVER co-resident (gfber -19 contention, Finding L):
#    load shim -> load TAs -> rmmod shim -> insmod goodix_fp.
#  * gfber is stateful; one wedge (-22) needs a fresh TA. reset_gfber does that
#    via the shim's force-unload without a reboot (Finding Q).
#
# Sensor touches are required only in the step5/step6 TOUCH sections, which prompt.
set -uo pipefail
H=poco
DIST=~/workspace/pocof1-kernel/dist/qsee22
OND=~/workspace/pocof1-kernel/fingerprint/on-device
MODDIR=/lib/modules/7.2.9-sdm845/extra

gsys(){ ssh $H 'dirname $(find /sys/devices -name ginit 2>/dev/null | head -1)'; }

step0_verify_clean(){ ssh $H 'uname -v; lsmod | grep -E "goodix_fp|qseecom|spi_geni" || echo clean'; }

# NEEDS YARON PRESENT (power-cycle recovery). RAM-boot + stage modules + scripts.
step1_ramboot(){
  ssh $H 'sudo systemctl reboot --reboot-argument=bootloader'
  until fastboot devices 2>/dev/null | grep -q fastboot; do sleep 3; done
  fastboot boot "$DIST/boot-fc.img"
  # Wi-Fi (poco) may not come back on the test kernel; fall back to USB (poco-usb).
  for t in $(seq 1 20); do sleep 3
    ssh -o ConnectTimeout=4 poco     uname -v 2>/dev/null && { H=poco;     break; }
    ssh -o ConnectTimeout=4 poco-usb uname -v 2>/dev/null && { H=poco-usb; break; }
  done
  echo "device up on H=$H"
  scp "$DIST"/goodix_fp.ko "$DIST"/qseecom_shim.ko $H:/tmp/
  scp "$OND"/gfload.py $H:/tmp/
  ssh $H "sudo install -m644 /tmp/goodix_fp.ko /tmp/qseecom_shim.ko $MODDIR/"
}

# Load gfber+fpcber via the shim, note the id, rmmod shim, insmod goodix_fp.
step2_load(){
  ssh $H "sudo dmesg -C
    sudo insmod $MODDIR/qseecom_shim.ko 2>/dev/null
    ID=\$(sudo python3 /tmp/gfload.py | sed -n 's/GFBER_ID=//p')
    echo gfber_id=\$ID
    sudo rmmod qseecom_shim
    sudo insmod $MODDIR/goodix_fp.ko gf_app_id=\$ID km_app_id=1
    dmesg | grep -iE 'goodix_fp ready|gf bufs|keymaster app' | tail"
}

# Cold init: DETECT/INIT/INIT_FINISHED (expect status=0) + sensor version.
step3_init(){
  GS=$(gsys)
  ssh $H "sudo dmesg -C; echo 1 | sudo tee $GS/ginit >/dev/null
    dmesg | grep -iE 'DETECT|INIT|setkey|keymaster\(' | tail"
  # version read (grp3): PRE_GET_VERSION(1036) then GET_VERSION(1037), len568
  ssh $H "echo '1036:568:3' | sudo tee $GS/gcmd >/dev/null
          echo '1037:568:3' | sudo tee $GS/gcmd >/dev/null
          dmesg | grep -iE 'gcmd grp3' | tail -4"
}

# Send ONE command on a FRESH gfber (reset + init first). gfber is stateful and
# wedges on wrong order/repeats (Finding N), so each gating probe must stand alone.
probe_one(){   # probe_one <arg1> <len> <grp> <label>
  GS=$(gsys)
  reset_gfber >/dev/null
  ssh $H "sudo dmesg -C; echo 1 | sudo tee $GS/ginit >/dev/null
    echo '$1:$2:$3' | sudo tee $GS/gcmd >/dev/null
    S=\$(dmesg | grep -iE 'gcmd grp' | tail -1)
    printf '%-14s %s\n' '$4' \"\$S\""
}

# NO-TOUCH gating probe: each command on its own fresh+inited gfber, status only.
# Reveals whether the TEST path (1060/1061) and the real path (1006/1007/1010) are
# gated BEFORE any finger. Nonzero = a precondition to satisfy; 0 = dispatched/armed.
step4_notouch_probe(){
  probe_one 1060 96  3 TEST_ENROLL     # grp3, no HAT
  probe_one 1061 120 3 TEST_AUTH       # grp3, no HAT
  probe_one 1006 104 1 PRE_ENROLL      # grp1
  probe_one 1007 176 1 ENROLL_zeroHAT  # grp1, zeroed HAT -> INVALID_HAT? = gatekeeper needed
  probe_one 1010 120 1 AUTHENTICATE    # grp1
  echo "GF_ERROR: 0=accepted 1070=UNKNOWN_CMD 1003=BAD_PARAMS 1010=GENERIC"
  echo "          1062=SENSOR_NOT_AVAILABLE; INVALID_HAT-class on 1007 => real enroll needs a HAT."
}

irqcount(){ ssh $H "grep goodix_fp /proc/interrupts | awk '{s=0;for(i=2;i<=NF-2;i++)s+=\$i;print s}'"; }

# Verify the enroll/auth command actually armed finger-detect: the goodix_fp IRQ
# count must climb while a finger is held. Per disasm, the HAL does NOT send a
# separate CAMERA_CAPTURE(1021) after 1007/1010 — the enroll/auth command itself
# arms; 1021 in the HAL success path is an acquired-info NOTIFY code, not a TA
# command. So do NOT auto-send 1021 (it is a different op and could clobber the
# one under test). Just report. If no IRQ movement, the fix is a deliberate next
# experiment: send CAMERA_CAPTURE(1021:96:1 > gcmd) BEFORE arming (that arming was
# verified in the standalone capture flow, Finding T), not blindly after.
arm_check(){   # arm_check <GS>
  local before after
  before=$(irqcount)
  echo ">>> HOLD a finger on the sensor for ~3s <<<"; echo ">>> Enter when held+lifted <<<"; read -r
  after=$(irqcount)
  echo "goodix_fp IRQ: $before -> $after  $([ "$after" = "$before" ] && echo '(NO movement — command did not arm finger-detect; see arm_check note)' || echo '(armed OK)')"
}

# TOUCH: TEST enroll. Arms ENROLL mode (stays armed over presses). Yaron presses
# the sensor several times; each press -> GPIO IRQ -> GF_CMD_IRQ pull -> trace.
step5_test_enroll(){
  GS=$(gsys)
  ssh $H "sudo dmesg -C; echo 1 | sudo tee $GS/enroll >/dev/null"   # grp3/1060 + arm
  arm_check "$GS"
  echo ">>> PRESS the fingerprint sensor now, lift, repeat ~8-10 times <<<"
  echo ">>> press Enter here when done <<<"; read -r
  ssh $H "cat $GS/autocap; echo '--- trace (changes only) ---'; cat $GS/trace
          echo '--- dmesg ---'; dmesg | grep -iE 'GF_CMD_IRQ|TEST_ENROLL|CAPTURE' | tail -20
          echo 0 | sudo tee $GS/autocap >/dev/null"
  echo "snaps (per-state headers) -> $DIST/snaps.bin"
  ssh $H "cat $GS/snaps" > "$DIST/snaps-enroll.bin"
}

# TOUCH: TEST authenticate (op_id=0, challenge=0). Press once; read match in trace.
step6_test_auth(){
  GS=$(gsys)
  ssh $H "sudo dmesg -C; echo '0:0:0' | sudo tee $GS/authenticate >/dev/null"  # grp3/1061 + arm
  arm_check "$GS"
  echo ">>> PRESS the enrolled finger once <<<"; echo ">>> Enter when done <<<"; read -r
  ssh $H "cat $GS/autocap; echo '--- trace (changes only) ---'; cat $GS/trace
          echo '--- dmesg ---'; dmesg | grep -iE 'GF_CMD_IRQ|AUTH|CAPTURE' | tail -20
          echo 0 | sudo tee $GS/autocap >/dev/null"
  ssh $H "cat $GS/snaps" > "$DIST/snaps-auth.bin"
}

# Recover a wedged gfber (-22) WITHOUT a reboot: drop driver, force-unload via shim,
# reload fresh, reattach driver.
reset_gfber(){
  ssh $H "sudo rmmod goodix_fp 2>/dev/null
    sudo insmod $MODDIR/qseecom_shim.ko 2>/dev/null
    ID=\$(sudo python3 /tmp/gfload.py | sed -n 's/GFBER_ID=//p'); echo gfber_id=\$ID
    sudo rmmod qseecom_shim
    sudo insmod $MODDIR/goodix_fp.ko gf_app_id=\$ID km_app_id=1"
}

echo "functions: step0_verify_clean step1_ramboot(YARON) step2_load step3_init"
echo "           step4_notouch_probe step5_test_enroll(TOUCH) step6_test_auth(TOUCH) reset_gfber"
echo "usage: source this file, then call the steps in order. H=$H DIST=$DIST"
