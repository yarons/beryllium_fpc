#!/usr/bin/env python3
# EXACT QTI keymaster generate_key wire format, RE'd from KeymasterHalDevice::generate_key_common:
#   req: [u32 cmd=0x108][u32 params_off=0x0c][u32 count=N][ N x 12B records ][ indirect blob data ]
#   record(12B): [u32 tag][value]  value by type (tag>>28):
#     1/2/3/4 ENUM/ENUM_REP/UINT/UINT_REP -> u32 (+4 pad)
#     5/6/0xA ULONG/DATE/ULONG_REP        -> u64
#     7 BOOL                              -> 1 byte (+pad)
#     8/9 BIGNUM/BYTES                    -> [u32 offset_from_buf_start][u32 len]; data in indirect region
#   resp: [i32 status][...][u32 blob_off @8][u32 blob_len @0xc]
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
def gen(params, cmd=0x108):
    ctypes.memset(a,0,SB)
    off=0x0c; rec=off
    indirect_cursor = off + len(params)*12   # indirect region begins after the records
    ind_pos = indirect_cursor
    for tag,val in params:
        t=tag&0xF0000000
        struct.pack_into("<I",buf,rec,tag)
        if t in (ENUM,ENUM_REP,UINT,UINT_REP): struct.pack_into("<I",buf,rec+4,val&0xffffffff)
        elif t in (ULONG,ULONG_REP,DATE):      struct.pack_into("<Q",buf,rec+4,val&((1<<64)-1))
        elif t==BOOL:                          struct.pack_into("<B",buf,rec+4,1 if val else 0)
        elif t in (BIGNUM,BYTES):
            data=val; struct.pack_into("<II",buf,rec+4,ind_pos,len(data))
            ctypes.memmove(a+ind_pos,data,len(data)); ind_pos+=len(data)
        rec+=12
    struct.pack_into("<III",buf,0,cmd,off,len(params))
    L=ind_pos
    r=send(L); return struct.unpack_from("<i",r,0)[0], r
ERR={0:"OK",-1:"ROT_SET",-2:"UNSUP_PURPOSE",-3:"INCOMPAT_PURPOSE",-4:"UNSUP_ALG",-5:"INCOMPAT_ALG",
 -6:"UNSUP_KEYSIZE",-7:"UNSUP_BLOCKMODE",-8:"INCOMPAT_BLOCKMODE",-9:"UNSUP_MACLEN",-10:"UNSUP_PAD",
 -11:"INCOMPAT_PAD",-12:"UNSUP_DIGEST",-13:"INCOMPAT_DIGEST",-14:"INVALID_EXPIRY",-25:"UNSUP_EC",
 -30:"VERIFICATION_FAILED",-38:"INVALID_ARG",-40:"INVALID_TAG",-52:"MISSING_MIN_MAC",-53:"KEY_RATE"}
def e(s): return ERR.get(s,"?")
ALG=0x10000002;SIZE=0x30000003;PURP=0x20000001;BLK=0x20000004;DIG=0x20000005;PAD=0x20000006
NOAUTH=0x700001f7;MINMAC=0x30000008;RSAEXP=0x500000c8;ECCURVE=0x1000000a;DATETIME=0x600002bd
CN = DATETIME  # creation datetime (ms). supply a value.
TS = 1760000000000
specs = {
 "AES256-ECB-NONE": [(ALG,32),(SIZE,256),(PURP,0),(PURP,1),(BLK,1),(PAD,1),(NOAUTH,1),(CN,TS)],
 "AES256-CBC-PKCS7":[(ALG,32),(SIZE,256),(PURP,0),(PURP,1),(BLK,2),(PAD,64),(NOAUTH,1),(CN,TS)],
 "AES128-CBC-NONE": [(ALG,32),(SIZE,128),(PURP,0),(PURP,1),(BLK,2),(PAD,1),(NOAUTH,1),(CN,TS)],
 "HMAC-SHA256":     [(ALG,128),(SIZE,256),(PURP,2),(PURP,3),(DIG,4),(MINMAC,256),(NOAUTH,1),(CN,TS)],
 "RSA2048-PKCS1":   [(ALG,1),(SIZE,2048),(RSAEXP,65537),(PURP,2),(PURP,3),(DIG,4),(PAD,5),(NOAUTH,1),(CN,TS)],
 "EC-P256":         [(ALG,3),(SIZE,256),(PURP,2),(PURP,3),(DIG,4),(NOAUTH,1),(CN,TS)],
 "EC-P256-curve":   [(ALG,3),(ECCURVE,1),(PURP,2),(PURP,3),(DIG,4),(NOAUTH,1),(CN,TS)],
}
for name,p in specs.items():
    st,r=gen(p)
    ok=""
    if st==0:
        bo,bl=struct.unpack_from("<II",r,8); ok="  KEY_BLOB off=%d len=%d blob[:24]=%s"%(bo,bl,r[bo:bo+24].hex())
    print("%-18s -> %d %-18s%s"%(name,st,e(st),ok))
os.close(fd)
