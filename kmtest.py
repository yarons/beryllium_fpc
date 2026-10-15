# keymaster 0x205 via the shim, HAL-style. Robust: guards mmap, prints errno per step,
# reads the FULL {status,offset,length} response triple. Goal: status==0.
import fcntl, os, struct, ctypes, sys
libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.mmap.restype = ctypes.c_void_p
libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
MAP_FAILED = (1 << 64) - 1
LOAD = 0xC0549707; SETMEM = 0xC0189708; SEND = 0xC0209703
SB = 0x4000   # 16KB: shim mmap allocs 2x tzmem (tz+aux) of this size; pool is small

def die(msg):
    print("FATAL:", msg); sys.exit(1)

fd = os.open("/dev/qseecom", os.O_RDWR)
print("opened /dev/qseecom fd=%d" % fd)

# LOAD keymaster64 (shim returns existing app_id if already loaded by bootloader)
req = bytearray(84); struct.pack_into("<64s", req, 12, b"keymaster64")
try:
    fcntl.ioctl(fd, LOAD, req, True)
    app_id = struct.unpack_from("<I", req, 80)[0]
    print("LOAD keymaster64 OK app_id=%d" % app_id)
except OSError as e:
    die("LOAD keymaster64: %s" % e)

# mmap shared buffer (shim allocates on mmap)
addr = libc.mmap(None, SB, 3, 1, fd, 0)
if addr == MAP_FAILED or addr == 0:
    die("mmap failed errno=%d (%s)" % (ctypes.get_errno(), os.strerror(ctypes.get_errno())))
print("mmap sb=0x%x" % addr)

# SET_MEM_PARAM: ifd=-1, offset=0, virt_sb_base=addr, sb_len=SB
try:
    fcntl.ioctl(fd, SETMEM, bytearray(struct.pack("<iiQI4x", -1, 0, addr, SB)), False)
    print("SET_MEM OK base=0x%x len=0x%x" % (addr, SB))
except OSError as e:
    die("SET_MEM: %s" % e)

buf = (ctypes.c_char * SB).from_address(addr)

RSP_OFF = 0x1000
def send(c0, c1, c2, req_len, rsp_len):
    ctypes.memset(addr, 0, SB)
    struct.pack_into("<III", buf, 0, c0, c1, c2)   # {cmd, ret_val, length} then zeroed tail
    # qseecom_send_cmd_req: {void* cmd_req_buf; u32 cmd_req_len; pad; void* resp_buf; u32 resp_len; pad}
    sc = bytearray(struct.pack("<QI4xQI4x", addr, req_len, addr + RSP_OFF, rsp_len))
    fcntl.ioctl(fd, SEND, sc, False)
    return struct.unpack_from("<III", buf, RSP_OFF)

# Matrix: HAL-faithful (req8/rsp256) vs FPC-faithful (req64/rsp1024) vs crosses.
cases = [("HAL  req8  rsp256 ", 0x205, 0x02, 0, 8,  256),
         ("FPC  req64 rsp1024", 0x205, 0x02, 0, 64, 1024),
         ("     req64 rsp256 ", 0x205, 0x02, 0, 64, 256),
         ("     req8  rsp1024", 0x205, 0x02, 0, 8,  1024)]
for desc, c0, c1, c2, rl, rspl in cases:
    try:
        st, off, ln = send(c0, c1, c2, rl, rspl)
        raw = bytes(buf[RSP_OFF:RSP_OFF + 16])
        print("%-18s status=0x%08x offset=%d length=%d  raw=%s  %s"
              % (desc, st, off, ln, raw.hex(), "SUCCESS" if st == 0 else "FAIL"))
    except OSError as e:
        print("%-18s SEND errno: %s" % (desc, e))

os.close(fd)
