# Drive gfber with the TRUE ABI (from gf_ca_invoke_command): QSEECom send_modified_cmd + dma-buf payload.
# send_buf[0x04]=cmd_id, [0x10]=arg1, [0x14]=payload phys (modfd patched), [0x18]=len; resp status@[0x40];
# response DATA written back into the payload dma_buf. ifd_data[0]={payload_fd, cmd_buf_offset=0x14}.
# Prove REAL dispatch: valid cmd 1000 vs bogus cmd must differ.
import fcntl, os, struct, ctypes, sys
libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.mmap.restype = ctypes.c_void_p
libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
MAP_FAILED = (1 << 64) - 1
LOAD = 0xC0549707; SETMEM = 0xC0189708; SEND_MODFD = 0xC0409704
DMA_HEAP_ALLOC = 0xC0184800
SB = 0x4000; PAY = 0x1000

def load_app(name):
    fd = os.open("/dev/qseecom", os.O_RDWR)
    r = bytearray(84); struct.pack_into("<64s", r, 12, name.encode())
    try:
        fcntl.ioctl(fd, LOAD, r, True); aid = struct.unpack_from("<I", r, 80)[0]
        print("LOAD %-10s app_id=%d" % (name, aid)); return fd, aid
    except OSError as e:
        print("LOAD %-10s FAIL %s" % (name, e)); os.close(fd); return None, 0

# dma-buf payload from /dev/dma_heap/system
def dmabuf_alloc(length):
    h = os.open("/dev/dma_heap/system", os.O_RDWR)
    buf = bytearray(struct.pack("<QIIQ", length, 0, 0x80002, 0))  # len, fd(out), fd_flags=O_RDWR|O_CLOEXEC, heap_flags
    fcntl.ioctl(h, DMA_HEAP_ALLOC, buf, True)
    _, fd, _, _ = struct.unpack("<QIIQ", buf)
    os.close(h)
    pm = libc.mmap(None, length, 3, 1, fd, 0)
    if pm == MAP_FAILED or pm == 0: raise OSError("dmabuf mmap failed errno=%d" % ctypes.get_errno())
    return fd, pm

# gfber needs fpcber resident for the key path; load gfber + fpcber (hold)
hold = []
fp_fd, _ = load_app("fpcber"); hold.append(fp_fd)
gf_fd, gf_id = load_app("gfber")
if gf_fd is None: sys.exit("no gfber")

addr = libc.mmap(None, SB, 3, 1, gf_fd, 0)
if addr == MAP_FAILED or addr == 0: sys.exit("sb mmap failed errno=%d" % ctypes.get_errno())
fcntl.ioctl(gf_fd, SETMEM, bytearray(struct.pack("<iiQI4x", -1, 0, addr, SB)), False)
sb = (ctypes.c_char * SB).from_address(addr)
pfd, pm = dmabuf_alloc(PAY)
pay = (ctypes.c_char * PAY).from_address(pm)

def gf_send(cmd_id, arg1=0, plen=256, pre=b""):
    ctypes.memset(addr, 0, 0x80)           # clear send_buf+resp header
    ctypes.memset(pm, 0, PAY)              # clear payload
    if pre: ctypes.memmove(pm, pre, len(pre))
    struct.pack_into("<I", sb, 0x04, cmd_id)   # cmd_id
    struct.pack_into("<I", sb, 0x10, arg1)     # arg1
    struct.pack_into("<I", sb, 0x18, plen)     # payload len
    # modfd req: cmd_req_buf@sb+0 len64, resp@sb+0x40 len64, ifd[0]={pfd, 0x14}
    req = struct.pack("<QI4xQI", addr, 64, addr + 0x40, 64)
    ifd = struct.pack("<iI", pfd, 0x14) + b"\x00" * 24   # ifd_data[0]..[3]
    buf = bytearray(req + ifd)
    buf += b"\x00" * (64 - len(buf)) if len(buf) < 64 else b""
    fcntl.ioctl(gf_fd, SEND_MODFD, buf, False)
    status = struct.unpack_from("<i", sb, 0x40)[0]
    aux = struct.unpack_from("<I", sb, 0x44)[0]
    pdata = bytes(pay[0:32])
    return status, aux, pdata

print("struct modfd len:", len(struct.pack("<QI4xQI", 0, 0, 0, 0)) + 32)
for desc, cmd in [("cmd 1000 (init)", 1000), ("cmd 0xBEEF (bogus)", 0xBEEF), ("cmd 1000 again", 1000)]:
    try:
        st, aux, pd = gf_send(cmd)
        print("%-20s -> status=%d (0x%x) aux=0x%x payload[0:16]=%s" % (desc, st, st & 0xffffffff, aux, pd[:16].hex()))
    except OSError as e:
        print("%-20s SEND errno %s" % (desc, e))

os.close(gf_fd)
for h in hold:
    if h: os.close(h)
