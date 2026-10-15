#!/usr/bin/env python3
# KM4 early-boot HMAC handshake then generate/gatekeeper. RE'd cmds:
#   get_hmac_sharing_parameters = 0x706 ; req=[0x706]; resp=[status][seed:32][nonce:32]
#   compute_shared_hmac         = 0x707 ; generate-style header [cmd][0x0c][count] + params
# Goal: does establishing the shared HMAC flip generate(0x108) off its frozen -8?
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
def raw(reqbytes,rl=0x2000):
    ctypes.memset(a,0,SB); ctypes.memmove(a,reqbytes,len(reqbytes)); return send(len(reqbytes),rl)
ENUM=0x10000000;ENUM_REP=0x20000000;UINT=0x30000000;BOOL=0x70000000
ALG=0x10000002;SIZE=0x30000003;PURP=0x20000001;BLK=0x20000004;PAD=0x20000006;NOAUTH=0x700001f7
def gen():
    ctypes.memset(a,0,SB); P=[(ALG,32),(SIZE,256),(PURP,0),(PURP,1),(BLK,1),(PAD,1),(NOAUTH,1)]
    off=0x0c;rec=off
    for tag,val in P:
        t=tag&0xF0000000; struct.pack_into("<I",buf,rec,tag)
        if t==BOOL: struct.pack_into("<B",buf,rec+4,val)
        else: struct.pack_into("<I",buf,rec+4,val)
        rec+=12
    struct.pack_into("<III",buf,0,0x108,off,len(P)); r=send(rec); return struct.unpack_from("<i",r,0)[0]

print("generate BEFORE handshake -> %d"%gen())
# 0x706
r=raw(struct.pack("<I",0x706)); st=struct.unpack_from("<i",r,0)[0]
seed=r[4:36]; nonce=r[36:68]
print("0x706 get_hmac_sharing -> status=%d"%st)
print("   seed =%s"%seed.hex()); print("   nonce=%s"%nonce.hex())
# 0x707 try several framings of a single participant param, re-test generate after each
def compute(frame):
    ctypes.memset(a,0,SB)
    if frame=="A":   # [cmd][0xc][count=1] + seed32+nonce32
        struct.pack_into("<III",buf,0,0x707,0x0c,1); body=seed+nonce; ctypes.memmove(a+0x0c,body,len(body)); L=0x0c+len(body)
    elif frame=="B": # + seed_len prefix
        struct.pack_into("<III",buf,0,0x707,0x0c,1); body=struct.pack("<I",32)+seed+nonce; ctypes.memmove(a+0x0c,body,len(body)); L=0x0c+len(body)
    elif frame=="C": # nonce first
        struct.pack_into("<III",buf,0,0x707,0x0c,1); body=nonce+seed; ctypes.memmove(a+0x0c,body,len(body)); L=0x0c+len(body)
    elif frame=="D": # [cmd][count@4] + body@8
        struct.pack_into("<II",buf,0,0x707,1); body=seed+nonce; ctypes.memmove(a+0x08,body,len(body)); L=0x08+len(body)
    r=send(L); return struct.unpack_from("<i",r,0)[0]
for fr in "ABCD":
    cst=compute(fr); g=gen()
    print("0x707 frame %s -> status=%d | generate -> %d%s"%(fr,cst,g,"  <<< UNLOCKED" if g==0 else ""))
os.close(fd)
