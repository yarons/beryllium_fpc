# Test hypothesis: keymaster 0x205 succeeds only when the FP TA (+cmnlib) is resident.
# Load gfber (and/or fpcber) on held handles first, THEN call keymaster64 0x205.
import fcntl, os, struct, ctypes, sys
libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.mmap.restype = ctypes.c_void_p
libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
MAP_FAILED = (1 << 64) - 1
LOAD = 0xC0549707; SETMEM = 0xC0189708; SEND = 0xC0209703
SB = 0x4000

def load_app(name):
    fd = os.open("/dev/qseecom", os.O_RDWR)
    req = bytearray(84); struct.pack_into("<64s", req, 12, name.encode())
    try:
        fcntl.ioctl(fd, LOAD, req, True)
        aid = struct.unpack_from("<I", req, 80)[0]
        print("LOAD %-12s OK app_id=%d" % (name, aid)); return fd, aid
    except OSError as e:
        print("LOAD %-12s FAIL %s" % (name, e)); os.close(fd); return None, 0

def keymaster_once(tag):
    fd, aid = load_app("keymaster64")
    if fd is None: return
    addr = libc.mmap(None, SB, 3, 1, fd, 0)
    if addr == MAP_FAILED or addr == 0:
        print("  mmap failed errno=%d" % ctypes.get_errno()); os.close(fd); return
    fcntl.ioctl(fd, SETMEM, bytearray(struct.pack("<iiQI4x", -1, 0, addr, SB)), False)
    buf = (ctypes.c_char * SB).from_address(addr)
    ctypes.memset(addr, 0, SB)
    struct.pack_into("<III", buf, 0, 0x205, 0x02, 0)
    sc = bytearray(struct.pack("<QI4xQI4x", addr, 8, addr + 0x1000, 256))
    try:
        fcntl.ioctl(fd, SEND, sc, False)
        st, off, ln = struct.unpack_from("<III", buf, 0x1000)
        print("  [%s] keymaster 0x205 -> status=0x%08x off=%d len=%d %s"
              % (tag, st, off, ln, "SUCCESS" if st == 0 else "FAIL"))
    except OSError as e:
        print("  [%s] SEND err %s" % (tag, e))
    os.close(fd)

print("== baseline: keymaster alone ==")
keymaster_once("alone")

print("== load cmnlib64 then keymaster ==")
h_cmn, _ = load_app("cmnlib64")
keymaster_once("after cmnlib64")

print("== load gfber (holds) then keymaster ==")
h_gf, _ = load_app("gfber")
keymaster_once("after gfber")

print("== load fpcber (holds) then keymaster ==")
h_fp, _ = load_app("fpcber")
keymaster_once("after fpcber")

for h in (h_cmn, h_gf, h_fp):
    if h is not None: os.close(h)
