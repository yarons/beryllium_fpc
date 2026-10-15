# Init + arm + pull a frame via GF_CMD_IRQ(1016). Bigger buffers (SB=0x8000) to fit a raw frame.
# Keep finger ON during the pulls.
import fcntl, os, struct, ctypes, time
libc=ctypes.CDLL("libc.so.6",use_errno=True); libc.mmap.restype=ctypes.c_void_p
libc.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]
MF=(1<<64)-1
LOAD=0xC0549707; UNLOAD=0x9709; SETMEM=0xC0189708; SEND=0xC0209703; SENDMF=0xC0409704; HEAP=0xC0184800
ENPWR=0x6707; ENCLK=0x40046705; RESET=0x6702; ENIRQ=0x6703
SB=0x8000; PAY=0x8000

g=os.open("/dev/goodix_fp",os.O_RDWR)
fcntl.ioctl(g,ENPWR); fcntl.ioctl(g,ENCLK,struct.pack("<I",19200000)); fcntl.ioctl(g,RESET)
def loadapp(n):
    fd=os.open("/dev/qseecom",os.O_RDWR); r=bytearray(84); struct.pack_into("<64s",r,12,n.encode())
    try: fcntl.ioctl(fd,LOAD,r,True); a=struct.unpack_from("<I",r,80)[0]
    except OSError: a=-1
    return fd,a
fd,_=loadapp("gfber")
try: fcntl.ioctl(fd,UNLOAD)
except OSError: pass
os.close(fd)
fp,_=loadapp("fpcber")
gf,gid=loadapp("gfber"); print("gfber id=%d"%gid)
try:
    a=libc.mmap(None,SB,3,1,gf,0)
    if a==MF or a==0: raise OSError("sb mmap errno=%d"%ctypes.get_errno())
    fcntl.ioctl(gf,SETMEM,bytearray(struct.pack("<iiQI4x",-1,0,a,SB)),False)
except OSError as e:
    print("SB mmap failed (tzmem too small for SB=0x%x): %s"%(SB,e)); os._exit(1)
sb=(ctypes.c_char*SB).from_address(a)
km,_=loadapp("keymaster64"); ka=libc.mmap(None,0x1000,3,1,km,0); fcntl.ioctl(km,SETMEM,bytearray(struct.pack("<iiQI4x",-1,0,ka,0x1000)),False)
kb=(ctypes.c_char*0x1000).from_address(ka)
h=os.open("/dev/dma_heap/system",os.O_RDWR); b=bytearray(struct.pack("<QIIQ",PAY,0,0x80002,0)); fcntl.ioctl(h,HEAP,b,True); _,pf,_,_=struct.unpack("<QIIQ",b); os.close(h)
pm=libc.mmap(None,PAY,3,1,pf,0); pay=(ctypes.c_char*PAY).from_address(pm)
def cmd(grp,arg1,plen,pre=b""):
    ctypes.memset(a,0,0x80); ctypes.memset(pm,0,PAY)
    if pre: ctypes.memmove(pm,pre,len(pre))
    struct.pack_into("<I",sb,0x04,grp); struct.pack_into("<I",sb,0x10,arg1); struct.pack_into("<I",sb,0x18,plen)
    req=struct.pack("<QI4xQI",a,64,a+0x40,64); ifd=struct.pack("<iI",pf,0x14)+b"\x00"*24
    buf=bytearray(req+ifd); buf+=b"\x00"*(64-len(buf))
    try: fcntl.ioctl(gf,SENDMF,buf,False); return struct.unpack_from("<i",sb,0x40)[0]
    except OSError as e: return "ERR:%s"%e
def framestat(n):
    bs=bytes(pay[0:n]); nz=sum(1 for c in bs if c);
    return "nonzero=%d/%d min=%d max=%d head=%s"%(nz,n,min(bs),max(bs),bs[:16].hex())
ctypes.memset(ka,0,0x1000); struct.pack_into("<III",kb,0,0x205,0x02,0)
fcntl.ioctl(km,SEND,bytearray(struct.pack("<QI4xQI4x",ka,8,ka+0x800,256)),False)
key256=bytes(kb[0x800:0x800+256])
print("setkey:",cmd(2,109,256,key256),"DETECT:",cmd(1,1000,356),"INIT:",cmd(1,1001,168),"INIT_FIN:",cmd(1,1005,100))
fcntl.ioctl(g,ENIRQ)
print("CAMERA_CAPTURE:",cmd(1,1021,96))
print(">>> FINGER ON THE SENSOR NOW — holding <<<")
for t in range(8):
    time.sleep(1)
    st=cmd(1,1016,0x6000)   # GF_CMD_IRQ pull frame, 24KB
    print("t%d GF_CMD_IRQ(1016) status=%s %s"%(t,st,framestat(0x6000)))
os.close(g)
