#!/usr/bin/env python3
# Load gfber FRESH (force-unload any stale instance) + fpcber (the keymaster
# get-key precondition, Finding E). Prints GFBER_ID=<n> for insmod goodix_fp.
# Both TAs stay resident after close(): the shim's release only frees buffers,
# it does NOT shut the app down (verified qs_release). Force-unload is only the
# explicit UNLOAD ioctl. Run as root with /dev/qseecom present (shim loaded).
import fcntl, os, struct, sys
LOAD = 0xC0549707
UNLOAD = 0x9709            # force app_shutdown (magic 0x97, Finding Q)

def loadapp(name):
    fd = os.open("/dev/qseecom", os.O_RDWR)
    r = bytearray(84)
    struct.pack_into("<64s", r, 12, name.encode())
    try:
        fcntl.ioctl(fd, LOAD, r, True)
        app = struct.unpack_from("<I", r, 80)[0]
    except OSError:
        app = -1
    return fd, app

fd, _ = loadapp("gfber")          # possibly stale/wedged from a prior run
try:
    fcntl.ioctl(fd, UNLOAD)       # force shutdown -> next load is a fresh TA
except OSError:
    pass
os.close(fd)

fp, _ = loadapp("fpcber")         # keymaster precondition; leave resident
gf, gid = loadapp("gfber")        # fresh gfber
os.close(fp)
os.close(gf)                      # TZ keeps both apps resident
print("GFBER_ID=%d" % gid)
sys.exit(0 if gid > 0 else 1)
