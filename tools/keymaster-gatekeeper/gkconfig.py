# keymaster configure(0x116) with OS_VERSION/OS_PATCHLEVEL, then retry GK_ENROLL(0x1001).
import fcntl, os, struct, ctypes, sys
libc=ctypes.CDLL("libc.so.6",use_errno=True); libc.mmap.restype=ctypes.c_void_p
libc.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]
MF=(1<<64)-1; LOAD=0xC0549707; SETMEM=0xC0189708; SEND=0xC0209703; SB=0x8000
def load(n):
    fd=os.open("/dev/qseecom",os.O_RDWR); r=bytearray(84); struct.pack_into("<64s",r,12,n.encode())
    try: fcntl.ioctl(fd,LOAD,r,True); return fd,struct.unpack_from("<I",r,80)[0]
    except OSError: os.close(fd); return None,0
fd,aid=load("keymaster64"); print("keymaster app_id=%d"%aid)
a=libc.mmap(None,SB,3,1,fd,0); fcntl.ioctl(fd,SETMEM,bytearray(struct.pack("<iiQI4x",-1,0,a,SB)),False)
buf=(ctypes.c_char*SB).from_address(a); RESP=0x2000
def send(reqlen):
    sc=bytearray(struct.pack("<QI4xQI4x",a,reqlen,a+RESP,0x400))
    fcntl.ioctl(fd,SEND,sc,False); return struct.unpack_from("<i",buf,RESP)[0]
OSVER=100000; PATCH=201901
OSVER_TAG=0x300002C1; PATCH_TAG=0x300002C2
def configure(fmt):
    ctypes.memset(a,0,SB)
    struct.pack_into("<III",buf,0,0x116,0x0c,2)   # cmd, params_off=0x0c, count=2
    if fmt==0:   # compact {tag,u32}
        struct.pack_into("<IIII",buf,0x0c, OSVER_TAG,OSVER, PATCH_TAG,PATCH); L=0x0c+16
    elif fmt==1: # {tag,u64}
        struct.pack_into("<IQIQ",buf,0x0c, OSVER_TAG,OSVER, PATCH_TAG,PATCH); L=0x0c+24
    elif fmt==3: # {tag, u32 value, pad} 12B/param (CORRECT per params_serialize)
        struct.pack_into("<IIIIII",buf,0x0c, OSVER_TAG,OSVER,0, PATCH_TAG,PATCH,0); L=0x0c+24
    else:        # {tag, pad, u64} 16B each
        struct.pack_into("<IIQ",buf,0x0c, OSVER_TAG,0,OSVER); struct.pack_into("<IIQ",buf,0x0c+16, PATCH_TAG,0,PATCH); L=0x0c+32
    try: return send(L)
    except OSError as e: return "ERR:%s"%e
def enroll(pin=b"1234"):
    ctypes.memset(a,0,SB)
    struct.pack_into("<II",buf,0,0x1001,0); struct.pack_into("<IIII",buf,0x08,0,0,0,0)
    struct.pack_into("<II",buf,0x18,0x20,len(pin)); ctypes.memmove(a+0x20,pin,len(pin))
    try: return send(0x20+len(pin))
    except OSError as e: return "ERR:%s"%e
print("baseline enroll:", enroll())
for fmt in (3,):
    st=configure(fmt)
    print("configure fmt%d -> status=%s   | enroll after -> %s"%(fmt,st,enroll()))
os.close(fd)
