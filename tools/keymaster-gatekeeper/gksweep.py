# Sweep uid + pw-length for GK_ENROLL(0x1001) to see if -30 (VERIFICATION_FAILED) ever changes.
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
def enroll(uid,pin):
    ctypes.memset(a,0,SB)
    struct.pack_into("<II",buf,0,0x1001,uid)
    struct.pack_into("<IIII",buf,0x08,0,0,0,0)           # curHandle+curPw null
    struct.pack_into("<II",buf,0x18,0x20,len(pin))       # desiredPw off/len
    ctypes.memmove(a+0x20,pin,len(pin))
    sc=bytearray(struct.pack("<QI4xQI4x",a,0x20+len(pin),a+RESP,0x400))
    try: fcntl.ioctl(fd,SEND,sc,False); return struct.unpack_from("<i",buf,RESP)[0]
    except OSError as e: return "ERR:%s"%e
for uid in (0,1,1000,10000,100000,0xdeadbeef):
    for pin in (b"1234", b"0000000000000000"):
        print("uid=%-10d pinlen=%2d -> status=%s"%(uid,len(pin),enroll(uid,pin)))
os.close(fd)
