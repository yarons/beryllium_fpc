import fcntl,os,struct,ctypes
libc=ctypes.CDLL("libc.so.6");libc.mmap.restype=ctypes.c_void_p
libc.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]
LOAD=0xC0549707;SETMEM=0xC0189708;SEND=0xC0209703;SB=0x8000
def load(n):
    fd=os.open("/dev/qseecom",os.O_RDWR);r=bytearray(84);struct.pack_into("<64s",r,12,n.encode())
    try:fcntl.ioctl(fd,LOAD,r,True);return fd,struct.unpack_from("<I",r,80)[0]
    except OSError:os.close(fd);return None,0
for n in("cmnlib64","gfber","fpcber"):load(n)
fd,_=load("keymaster64")
a=libc.mmap(None,SB,3,1,fd,0);fcntl.ioctl(fd,SETMEM,bytearray(struct.pack("<iiQI4x",-1,0,a,SB)),False)
buf=(ctypes.c_char*SB).from_address(a);RESP=0x2000
def send(L):
    fcntl.ioctl(fd,SEND,bytearray(struct.pack("<QI4xQI4x",a,L,a+RESP,0x400)),False)
    return struct.unpack_from("<i",buf,RESP)[0]
def gen(cmd,params,off0=0x0c):
    ctypes.memset(a,0,SB);struct.pack_into("<III",buf,0,cmd,off0,len(params))
    o=off0
    for t,v in params:struct.pack_into("<III",buf,o,t,v,0);o+=12
    return send(o)
# AES-128 (ENUM tags). Also try HMAC/EC. And drop NO_AUTH_REQUIRED (maybe the bad tag).
AES=[(0x10000002,32),(0x30000003,128),(0x20000001,0),(0x20000004,1),(0x20000006,1)]
AES_auth=AES+[(0x700001f7,1)]
for cmd in (0x508,0x108):
    print("GENERATE cmd=0x%03x AES(noauth-less)=%d  AES+noauth=%d  minimal(alg+size)=%d"%(
        cmd, gen(cmd,AES), gen(cmd,AES_auth), gen(cmd,[(0x10000002,32),(0x30000003,128)])))
# GET_VERSION (0x200, lk2nd util) — simple, tells if util cmds work
ctypes.memset(a,0,SB);struct.pack_into("<I",buf,0,0x200)
print("GET_VERSION(0x200) -> %d"%send(4))
# READ_LK_DEVICE_STATE (0x202)
ctypes.memset(a,0,SB);struct.pack_into("<I",buf,0,0x202)
print("READ_LK_DEVICE_STATE(0x202) -> %d  resp=%s"%(send(4), bytes(buf[RESP:RESP+16]).hex()))
os.close(fd)
