#!/usr/bin/env python3
# Establish the keymaster shared-HMAC key (the ISharedSecret boot step pmOS skips), then retry
# gatekeeper enroll. KM_GET_HMAC_SHARING_PARAMETERS=0x706, KM_COMPUTE_SHARED_HMAC=0x707 (RE'd from
# KeymasterHalDevice::get_hmac_sharing_parameters/compute_shared_hmac). hmac_sharing_params_t = 64B.
import fcntl, os, struct, ctypes, sys
libc=ctypes.CDLL("libc.so.6",use_errno=True); libc.mmap.restype=ctypes.c_void_p
libc.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]
MF=(1<<64)-1; LOAD=0xC0549707; SETMEM=0xC0189708; SEND=0xC0209703; SB=0x8000
def load(n):
    fd=os.open("/dev/qseecom",os.O_RDWR); r=bytearray(84); struct.pack_into("<64s",r,12,n.encode())
    try: fcntl.ioctl(fd,LOAD,r,True); return fd,struct.unpack_from("<I",r,80)[0]
    except OSError as e: os.close(fd); return None,0
# fpcber resident helped 0x205; load the usual set (ignore already-loaded)
for n in ("cmnlib64","gfber","fpcber"): load(n)
fd,aid=load("keymaster64"); print("keymaster app_id=%d"%aid)
a=libc.mmap(None,SB,3,1,fd,0); fcntl.ioctl(fd,SETMEM,bytearray(struct.pack("<iiQI4x",-1,0,a,SB)),False)
buf=(ctypes.c_char*SB).from_address(a); RESP=0x2000
def send(reqlen,resplen=0x600):
    sc=bytearray(struct.pack("<QI4xQI4x",a,reqlen,a+RESP,resplen))
    fcntl.ioctl(fd,SEND,sc,False); return bytes(buf[RESP:RESP+0x120])
def hexdump(b,n=0x80):
    for i in range(0,n,16): print("   %03x: "%i+" ".join("%02x"%b[i+j] for j in range(16)))

# --- 0x706 get_hmac_sharing_parameters: request = [0x706] (4 bytes) ---
ctypes.memset(a,0,SB); struct.pack_into("<I",buf,0,0x706)
r=send(4); st=struct.unpack_from("<i",r,0)[0]
print("GET_HMAC_SHARING_PARAMS(0x706) -> status=%d (0x%08x)"%(st,st&0xffffffff)); hexdump(r,0x70)
# params (seed32+nonce32) typically follow the 4-byte status; grab 64B after status
params=r[4:4+64]
print("params[0:16]=%s"%params[:16].hex())

# --- 0x707 compute_shared_hmac: [0x707][off=0x0c][count=1] + 64B params ---
ctypes.memset(a,0,SB); struct.pack_into("<III",buf,0,0x707,0x0c,1)
ctypes.memmove(a+0x0c,params,64)
r=send(0x0c+64); st=struct.unpack_from("<i",r,0)[0]
print("COMPUTE_SHARED_HMAC(0x707) -> status=%d (0x%08x)"%(st,st&0xffffffff)); hexdump(r,0x30)

# --- retry gatekeeper enroll 0x1001 ---
PIN=b"1234"
ctypes.memset(a,0,SB)
struct.pack_into("<II",buf,0,0x1001,1); struct.pack_into("<IIII",buf,0x08,0,0,0,0)
struct.pack_into("<II",buf,0x18,0x20,len(PIN)); ctypes.memmove(a+0x20,PIN,len(PIN))
r=send(0x20+len(PIN)); st=struct.unpack_from("<i",r,0)[0]
print("GK_ENROLL(0x1001) after shared-hmac -> status=%d (0x%08x)  %s"%(st,st&0xffffffff,
      "<<< CLEARED!" if st==0 else ("still -30" if st==-30 else "CHANGED")))
hexdump(r,0x40)
os.close(fd)
