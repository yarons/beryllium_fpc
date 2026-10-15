#!/usr/bin/env python3
# Discriminator: (1) is 0x508 -40 frozen vs param content? (2) which cmd-id fully parses an AuthSet?
import fcntl, os, struct, ctypes
libc = ctypes.CDLL("libc.so.6"); libc.mmap.restype = ctypes.c_void_p
libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
LOAD=0xC0549707; SETMEM=0xC0189708; SEND=0xC0209703; SB=0x8000
def load(n):
    fd=os.open("/dev/qseecom",os.O_RDWR); r=bytearray(84); struct.pack_into("<64s",r,12,n.encode())
    try: fcntl.ioctl(fd,LOAD,r,True); return fd,struct.unpack_from("<I",r,80)[0]
    except OSError: os.close(fd); return None,0
for n in ("cmnlib64","gfber","fpcber"): load(n)
fd,_=load("keymaster64")
a=libc.mmap(None,SB,3,1,fd,0); fcntl.ioctl(fd,SETMEM,bytearray(struct.pack("<iiQI4x",-1,0,a,SB)),False)
buf=(ctypes.c_char*SB).from_address(a); RESP=0x2000
def send(L,rl=0x400):
    fcntl.ioctl(fd,SEND,bytearray(struct.pack("<QI4xQI4x",a,L,a+RESP,rl)),False)
    return struct.unpack_from("<i",buf,RESP)[0]
def authset(params):
    ind=b""; el=b""
    for tag,val in params:
        t=tag&0xF0000000; e=struct.pack("<I",tag)
        if t in(0x10000000,0x20000000,0x30000000,0x40000000): e+=struct.pack("<I",val&0xffffffff)
        elif t in(0x50000000,0xA0000000,0x60000000): e+=struct.pack("<Q",val)
        elif t==0x70000000: e+=bytes([1 if val else 0])
        elif t in(0x80000000,0x90000000): e+=struct.pack("<II",len(val),len(ind)); ind+=val
        el+=e
    return struct.pack("<I",len(ind))+ind+struct.pack("<II",len(params),len(el))+el
def gen(cmd,params):
    aset=authset(params); ctypes.memset(a,0,SB)
    struct.pack_into("<III",buf,0,cmd,0x0c,len(aset)); ctypes.memmove(a+0x0c,aset,len(aset))
    return send(0x0c+len(aset))
ERR={0:"OK",-1:"ROT_ALREADY_SET",-2:"UNSUP_PURPOSE",-4:"UNSUP_ALG",-6:"UNSUP_KEYSIZE",-7:"UNSUP_BLOCKMODE",
 -8:"INCOMPAT_BLOCKMODE",-10:"UNSUP_PADDING",-12:"UNSUP_DIGEST",-15:"INVALID_USER_ID",-21:"INVALID_INPUT_LEN",
 -30:"VERIFICATION_FAILED",-38:"INVALID_ARG",-40:"INVALID_TAG",-64:"UNIMPLEMENTED",-66:"UNKNOWN"}
def e(s): return ERR.get(s,"?")
AES=[(0x10000002,32),(0x30000003,128),(0x20000001,0),(0x20000001,1),(0x20000004,2),(0x20000006,1),(0x700001f7,1)]
# (1) frozen? vary content on 0x508
print("=== 0x508 content variation ===")
for name,p in [("empty",[]),("alg-only",[(0x10000002,32)]),("badsize",[(0x10000002,32),(0x30000003,7)]),
               ("badalg",[(0x10000002,999),(0x30000003,128)]),("full-AES",AES),
               ("EC",[(0x10000002,3),(0x30000003,256),(0x20000001,2),(0x20000001,3),(0x20000005,4),(0x700001f7,1)])]:
    s=gen(0x508,p); print("  %-10s -> %d %s"%(name,s,e(s)))
# (2) cmd-id sweep with minimal AES, look for deep parse (-2/-4/-6/-7/-10/-12) or OK
print("=== cmd-id sweep (minimal AES, off_len) ; show non -38/-64/-66 ===")
for cmd in list(range(0x100,0x120))+list(range(0x200,0x210))+list(range(0x500,0x520)):
    s=gen(cmd,AES)
    if s not in (-38,-64,-66,-40): print("  cmd=0x%03x -> %d %s"%(cmd,s,e(s)))
os.close(fd)
