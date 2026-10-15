# Send KEYMASTER_SET_ROT (0x201) from userspace (lk2nd's boot_verifier.c flow), ORANGE/unlocked:
# final_digest = SHA256(is_unlocked_byte). req = {cmd_id, rot_offset=12, rot_size=32} + 32B digest.
# Then test if keymaster crypto/gatekeeper unblocks.
import fcntl,os,struct,ctypes,hashlib
libc=ctypes.CDLL("libc.so.6"); libc.mmap.restype=ctypes.c_void_p
libc.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]
LOAD=0xC0549707;SETMEM=0xC0189708;SEND=0xC0209703;SB=0x8000
def load(n):
    fd=os.open("/dev/qseecom",os.O_RDWR);r=bytearray(84);struct.pack_into("<64s",r,12,n.encode())
    try:fcntl.ioctl(fd,LOAD,r,True);return fd,struct.unpack_from("<I",r,80)[0]
    except OSError:os.close(fd);return None,0
for n in("cmnlib64","gfber","fpcber"):load(n)
fd,aid=load("keymaster64");print("keymaster app_id=%d"%aid)
a=libc.mmap(None,SB,3,1,fd,0);fcntl.ioctl(fd,SETMEM,bytearray(struct.pack("<iiQI4x",-1,0,a,SB)),False)
buf=(ctypes.c_char*SB).from_address(a);RESP=0x2000
def send(L,rl=0x400):
    fcntl.ioctl(fd,SEND,bytearray(struct.pack("<QI4xQI4x",a,L,a+RESP,rl)),False)
    return bytes(buf[RESP:RESP+0x40])
def st(r):return struct.unpack_from("<i",r,0)[0]
def gen():   # generate_key 0x508 AES-128 (the crypto canary)
    ctypes.memset(a,0,SB);struct.pack_into("<III",buf,0,0x508,0x0c,6)
    for i,(t,v) in enumerate([(0x10000002,32),(0x30000003,128),(0x20000001,0),(0x20000004,1),(0x20000006,1),(0x700001f7,1)]):
        struct.pack_into("<III",buf,0x0c+i*12,t,v,0)
    return st(send(0x0c+72))
def gkenroll():  # gatekeeper enroll 0x1001
    ctypes.memset(a,0,SB);struct.pack_into("<II",buf,0,0x1001,1);struct.pack_into("<IIII",buf,0x08,0,0,0,0)
    struct.pack_into("<II",buf,0x18,0x20,4);ctypes.memmove(a+0x20,b"1234",4)
    return st(send(0x24))
print("BEFORE: generate_key=%d  gk_enroll=%d"%(gen(),gkenroll()))
for unlocked in (1,0):
    digest=hashlib.sha256(bytes([unlocked])).digest()
    ctypes.memset(a,0,SB)
    struct.pack_into("<III",buf,0,0x201,12,32)   # cmd_id=SET_ROT, rot_offset=12, rot_size=32
    ctypes.memmove(a+12,digest,32)
    r=send(12+32); s=st(r)
    print("SET_ROT(0x201) is_unlocked=%d digest=%s... -> status=%d"%(unlocked,digest[:6].hex(),s))
    print("  AFTER: generate_key=%d  gk_enroll=%d"%(gen(),gkenroll()))
os.close(fd)
