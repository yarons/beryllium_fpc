#!/usr/bin/env python3
# Call configure(0x116) with OS_VERSION+OS_PATCHLEVEL (never set on pmOS - no Android HAL ran),
# then generate_key. Same wire format RE'd from generate_key_common / configure.
import fcntl, os, struct, ctypes
libc = ctypes.CDLL("libc.so.6"); libc.mmap.restype = ctypes.c_void_p
libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
LOAD=0xC0549707; SETMEM=0xC0189708; SEND=0xC0209703; SB=0x10000
def load(n):
    fd=os.open("/dev/qseecom",os.O_RDWR); r=bytearray(84); struct.pack_into("<64s",r,12,n.encode())
    try: fcntl.ioctl(fd,LOAD,r,True); return fd,struct.unpack_from("<I",r,80)[0]
    except OSError: os.close(fd); return None,0
for n in ("cmnlib64","gfber","fpcber"): load(n)
fd,aid=load("keymaster64"); print("km app_id=%d"%aid)
a=libc.mmap(None,SB,3,1,fd,0); fcntl.ioctl(fd,SETMEM,bytearray(struct.pack("<iiQI4x",-1,0,a,SB)),False)
buf=(ctypes.c_char*SB).from_address(a); RESP=0x8000
def send(L,rl=0x2000):
    fcntl.ioctl(fd,SEND,bytearray(struct.pack("<QI4xQI4x",a,L,a+RESP,rl)),False)
    return bytes(buf[RESP:RESP+rl])
ENUM=0x10000000;ENUM_REP=0x20000000;UINT=0x30000000;UINT_REP=0x40000000
ULONG=0x50000000;DATE=0x60000000;BOOL=0x70000000;BIGNUM=0x80000000;BYTES=0x90000000;ULONG_REP=0xA0000000
def cmd(c, params):
    ctypes.memset(a,0,SB); off=0x0c; rec=off; ind=off+len(params)*12
    for tag,val in params:
        t=tag&0xF0000000; struct.pack_into("<I",buf,rec,tag)
        if t in (ENUM,ENUM_REP,UINT,UINT_REP): struct.pack_into("<I",buf,rec+4,val&0xffffffff)
        elif t in (ULONG,ULONG_REP,DATE):      struct.pack_into("<Q",buf,rec+4,val&((1<<64)-1))
        elif t==BOOL:                          struct.pack_into("<B",buf,rec+4,1 if val else 0)
        elif t in (BIGNUM,BYTES): struct.pack_into("<II",buf,rec+4,ind,len(val)); ctypes.memmove(a+ind,val,len(val)); ind+=len(val)
        rec+=12
    struct.pack_into("<III",buf,0,c,off,len(params))
    r=send(ind); return struct.unpack_from("<i",r,0)[0], r
ERR={0:"OK",-1:"ROT_SET",-4:"UNSUP_ALG",-6:"UNSUP_KEYSIZE",-8:"INCOMPAT_BLOCKMODE",-30:"VERIF_FAIL",
     -38:"INVALID_ARG",-40:"INVALID_TAG",-66:"NOT_CONFIGURED"}
def e(s): return ERR.get(s,"?")
OSVER=0x300002c1; OSPATCH=0x300002c2
ALG=0x10000002;SIZE=0x30000003;PURP=0x20000001;BLK=0x20000004;PAD=0x20000006;NOAUTH=0x700001f7
AES=[(ALG,32),(SIZE,256),(PURP,0),(PURP,1),(BLK,1),(PAD,1),(NOAUTH,1)]
def gen():
    st,r=cmd(0x108,AES)
    if st==0:
        bo,bl=struct.unpack_from("<II",r,8); return st,"KEY_BLOB off=%d len=%d %s"%(bo,bl,r[bo:bo+24].hex())
    return st,e(st)
# baseline (no configure) in THIS fresh session
print("generate (pre-configure) -> %s"%(gen(),))
for ver,patch in [(100000,202001),(0,0),(90000,201909),(110000,202012)]:
    st,_=cmd(0x116,[(OSVER,ver),(OSPATCH,patch)])
    gst,gmsg=gen()
    print("configure(ver=%d,patch=%d) -> %d %-10s | generate -> %d %s"%(ver,patch,st,e(st),gst,gmsg))
os.close(fd)
