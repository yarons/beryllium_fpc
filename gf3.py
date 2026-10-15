# Proof-of-life + init sequence with the REAL GF_CMD map.
# Power/clock/reset via /dev/goodix_fp ioctls, then run gfber TA commands via /dev/qseecom shim.
# GF_CMD: 1000 DETECT_SENSOR,1001 INIT,1003 DOWNLOAD_FW,1004 DOWNLOAD_CFG,1005 INIT_FINISHED,
#         1034 TEST_SPI,1037 TEST_GET_VERSION,1057 TEST_SENSOR_VALIDITY. cmd_id=1 group, arg1=sub.
import fcntl, os, struct, ctypes, sys
libc=ctypes.CDLL("libc.so.6",use_errno=True); libc.mmap.restype=ctypes.c_void_p
libc.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]
MF=(1<<64)-1
LOAD=0xC0549707; SETMEM=0xC0189708; SEND=0xC0209703; SENDMF=0xC0409704; HEAP=0xC0184800
RESET=0x6702; ENSPICLK=0x40046705; ENPWR=0x6707
SB=0x1000; PAY=0x1000

# ---- power/clock/reset the sensor ----
try:
    g=os.open("/dev/goodix_fp",os.O_RDWR)
    fcntl.ioctl(g,ENPWR); print("ENABLE_POWER ok")
    fcntl.ioctl(g,ENSPICLK,struct.pack("<I",19200000)); print("ENABLE_SPI_CLK ok")
    fcntl.ioctl(g,RESET); print("RESET ok")
except OSError as e: print("power/clk ioctl:",e)

def load(n):
    fd=os.open("/dev/qseecom",os.O_RDWR); r=bytearray(84); struct.pack_into("<64s",r,12,n.encode())
    try: fcntl.ioctl(fd,LOAD,r,True); aid=struct.unpack_from("<I",r,80)[0]; print("LOAD %-11s id=%d"%(n,aid)); return fd,aid
    except OSError as e: print("LOAD %-11s %s"%(n,e)); os.close(fd); return None,0
def mmsb(fd):
    a=libc.mmap(None,SB,3,1,fd,0)
    if a==MF or a==0: sys.exit("sb mmap %d"%ctypes.get_errno())
    fcntl.ioctl(fd,SETMEM,bytearray(struct.pack("<iiQI4x",-1,0,a,SB)),False); return a
def dmabuf(n):
    h=os.open("/dev/dma_heap/system",os.O_RDWR); b=bytearray(struct.pack("<QIIQ",n,0,0x80002,0))
    fcntl.ioctl(h,HEAP,b,True); _,fd,_,_=struct.unpack("<QIIQ",b); os.close(h)
    pm=libc.mmap(None,n,3,1,fd,0)
    if pm==MF or pm==0: sys.exit("dmabuf mmap %d"%ctypes.get_errno())
    return fd,pm

fp,_=load("fpcber")
km,_=load("keymaster64"); ka=mmsb(km); kb=(ctypes.c_char*SB).from_address(ka)
ctypes.memset(ka,0,SB); struct.pack_into("<III",kb,0,0x205,0x02,0)
fcntl.ioctl(km,SEND,bytearray(struct.pack("<QI4xQI4x",ka,8,ka+0x800,256)),False)
key256=bytes(kb[0x800:0x800+256]); print("keymaster:",struct.unpack_from("<III",kb,0x800))

gf,gid=load("gfber"); a=mmsb(gf); sb=(ctypes.c_char*SB).from_address(a)
pfd,pm=dmabuf(PAY); pay=(ctypes.c_char*PAY).from_address(pm)

def cmd(arg1,plen=256,pre=b"",cmdgrp=1):
    ctypes.memset(a,0,0x80); ctypes.memset(pm,0,PAY)
    if pre: ctypes.memmove(pm,pre,len(pre))
    struct.pack_into("<I",sb,0x04,cmdgrp); struct.pack_into("<I",sb,0x10,arg1); struct.pack_into("<I",sb,0x18,plen)
    req=struct.pack("<QI4xQI",a,64,a+0x40,64); ifd=struct.pack("<iI",pfd,0x14)+b"\x00"*24
    buf=bytearray(req+ifd); buf+=b"\x00"*(64-len(buf))
    try: fcntl.ioctl(gf,SENDMF,buf,False)
    except OSError as e: return None,None,b"ERR:%s"%str(e).encode()
    return struct.unpack_from("<i",sb,0x40)[0], struct.unpack_from("<i",sb,0x44)[0], bytes(pay[0:32])
def run(name,arg1,cmdgrp=1,pre=b""):
    r0,r1,pd=cmd(arg1,256,pre,cmdgrp)
    print("%-22s (c%d/a%d) -> r[40]=%s r[44]=%s pay=%s"%(name,cmdgrp,arg1,r0,r1,pd.hex()))

# setkey first (cmd2/arg109)
run("SETKEY",109,2,key256)
# proof of life (read sensor)
run("DETECT_SENSOR",1000)
run("TEST_GET_VERSION",1037)
run("TEST_SPI",1034)
run("TEST_SENSOR_VALIDITY",1057)
# init sequence
run("DOWNLOAD_FW",1003)
run("DOWNLOAD_CFG",1004)
run("INIT",1001)
run("INIT_FINISHED",1005)
run("DETECT_SENSOR(post)",1000)
run("TEST_GET_VERSION(post)",1037)

os.close(gf); os.close(km)
if fp: os.close(fp)
