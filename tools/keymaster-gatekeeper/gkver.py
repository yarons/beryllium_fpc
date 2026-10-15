#!/usr/bin/env python3
import fcntl, os, struct, ctypes
libc = ctypes.CDLL("libc.so.6"); libc.mmap.restype = ctypes.c_void_p
libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
LOAD=0xC0549707; SETMEM=0xC0189708; SEND=0xC0209703; SENDMF=0xC0409704; SB=0x10000; FAR=0x8000
def load(n):
    fd=os.open("/dev/qseecom",os.O_RDWR); r=bytearray(84); struct.pack_into("<64s",r,12,n.encode())
    try: fcntl.ioctl(fd,LOAD,r,True); return fd,struct.unpack_from("<I",r,80)[0]
    except OSError: os.close(fd); return None,0
for n in ("cmnlib64","gfber","fpcber"): load(n)
fd,aid=load("keymaster64"); print("km app_id=%d"%aid)
a=libc.mmap(None,SB,3,1,fd,0); fcntl.ioctl(fd,SETMEM,bytearray(struct.pack("<iiQI4x",-1,0,a,SB)),False)
buf=(ctypes.c_char*SB).from_address(a)
BOOL=0x70000000
ALG=0x10000002;SIZE=0x30000003;PURP=0x20000001;BLK=0x20000004;PAD=0x20000006;NOAUTH=0x700001f7
P=[(ALG,32),(SIZE,256),(PURP,0),(PURP,1),(BLK,1),(PAD,1),(NOAUTH,1)]
def build_gen(off_base):
    rec=off_base
    for tag,val in P:
        t=tag&0xF0000000; struct.pack_into("<I",buf,rec,tag)
        if t==BOOL: struct.pack_into("<B",buf,rec+4,val)
        else: struct.pack_into("<I",buf,rec+4,val)
        rec+=12
    struct.pack_into("<III",buf,0,0x108,off_base,len(P)); return rec  # reqlen
def send_plain(reqlen, resp_off, rl=0x1000):
    fcntl.ioctl(fd,SEND,bytearray(struct.pack("<QI4xQI4x",a,reqlen,a+resp_off,rl)),False)
    return struct.unpack_from("<i",buf,resp_off)[0]
# 1) version / device-state full dumps
for c in (0x200,0x202,0x203,0x204,0x207):
    ctypes.memset(a,0,SB); struct.pack_into("<I",buf,0,c)
    st=send_plain(4,FAR); print("cmd 0x%03x -> status=%d resp[0:32]=%s"%(c,st,bytes(buf[FAR:FAR+32]).hex()))
# 2) generate, resp FAR (FAR) vs CONTIGUOUS (right after req)
ctypes.memset(a,0,SB); rl=build_gen(0x0c)
print("generate resp@0x10000 (far)        -> %d"%send_plain(rl,FAR))
ctypes.memset(a,0,SB); rl=build_gen(0x0c)
# contiguous: resp right after request, 16-byte aligned
resp_off=(rl+0xf)&~0xf
print("generate resp@req+reqlen (contig)  -> %d"%send_plain(rl,resp_off))
# 3) generate via MODIFIED cmd (zero ifd_data)
ctypes.memset(a,0,SB); rl=build_gen(0x0c); resp_off=FAR
# struct qseecom_send_modified_cmd_req { void*req; u32 rlen; void*resp; u32 resplen; ifd[4]{i32 fd;u32 off} }
mf=struct.pack("<QI4xQI4x", a, rl, a+resp_off, 0x1000) + b"\x00"*(4*8)
try:
    fcntl.ioctl(fd,SENDMF,bytearray(mf),False); print("generate MODIFIED cmd -> %d"%struct.unpack_from("<i",buf,resp_off)[0])
except OSError as e: print("generate MODIFIED cmd -> ioctl err %s"%e)
os.close(fd)
