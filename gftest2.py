# Full corrected gfber open_session + init, TRUE ABI (from gf_ca_open_session/invoke_command disasm):
#   get_key_from_keymaster(buf,256) ; gf_ca_invoke_command(cmd_id=2, arg1=109, data=keybuf, len=256)
# invoke wire: send_buf[0x04]=cmd_id,[0x10]=arg1,[0x14]=payload phys(modfd),[0x18]=len; resp status@[0x40];
# response data written back into the payload dma_buf. ifd[0]={payload_fd, 0x14}.
import fcntl, os, struct, ctypes, sys
libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.mmap.restype = ctypes.c_void_p
libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
MF = (1 << 64) - 1
LOAD=0xC0549707; SETMEM=0xC0189708; SEND=0xC0209703; SENDMF=0xC0409704; HEAP=0xC0184800
SB=0x4000; PAY=0x1000

def load(name):
    fd=os.open("/dev/qseecom",os.O_RDWR); r=bytearray(84); struct.pack_into("<64s",r,12,name.encode())
    try: fcntl.ioctl(fd,LOAD,r,True); aid=struct.unpack_from("<I",r,80)[0]; print("LOAD %-10s id=%d"%(name,aid)); return fd,aid
    except OSError as e: print("LOAD %-10s FAIL %s"%(name,e)); os.close(fd); return None,0

def mmsb(fd):
    a=libc.mmap(None,SB,3,1,fd,0)
    if a==MF or a==0: sys.exit("sb mmap errno=%d"%ctypes.get_errno())
    fcntl.ioctl(fd,SETMEM,bytearray(struct.pack("<iiQI4x",-1,0,a,SB)),False)
    return a

def dmabuf(n):
    h=os.open("/dev/dma_heap/system",os.O_RDWR); b=bytearray(struct.pack("<QIIQ",n,0,0x80002,0))
    fcntl.ioctl(h,HEAP,b,True); _,fd,_,_=struct.unpack("<QIIQ",b); os.close(h)
    pm=libc.mmap(None,n,3,1,fd,0)
    if pm==MF or pm==0: sys.exit("dmabuf mmap errno=%d"%ctypes.get_errno())
    return fd,pm

# ---- keymaster: need fpcber resident ----
fp_fd,_=load("fpcber")
km_fd,km_id=load("keymaster64"); ka=mmsb(km_fd); kb=(ctypes.c_char*SB).from_address(ka)
ctypes.memset(ka,0,SB); struct.pack_into("<III",kb,0,0x205,0x02,0)
fcntl.ioctl(km_fd,SEND,bytearray(struct.pack("<QI4xQI4x",ka,8,ka+0x1000,256)),False)
kst,koff,klen=struct.unpack_from("<III",kb,0x1000)
key256=bytes(kb[0x1000:0x1000+256])
print("keymaster 0x205 -> status=0x%x off=%d len=%d"%(kst,koff,klen))

# ---- gfber ----
gf_fd,gf_id=load("gfber"); a=mmsb(gf_fd); sb=(ctypes.c_char*SB).from_address(a)
pfd,pm=dmabuf(PAY); pay=(ctypes.c_char*PAY).from_address(pm)

def gf(cmd_id,arg1,plen,pre=b""):
    ctypes.memset(a,0,0x80); ctypes.memset(pm,0,PAY)
    if pre: ctypes.memmove(pm,pre,len(pre))
    import time
    struct.pack_into("<I",sb,0x00,1); struct.pack_into("<I",sb,0x04,cmd_id)
    struct.pack_into("<Q",sb,0x08,int(time.time())&0xffffffff); struct.pack_into("<I",sb,0x10,arg1); struct.pack_into("<I",sb,0x18,plen)
    req=struct.pack("<QI4xQI",a,64,a+0x40,64); ifd=struct.pack("<iI",pfd,0x14)+b"\x00"*24
    buf=bytearray(req+ifd); buf+=b"\x00"*(64-len(buf))
    fcntl.ioctl(gf_fd,SENDMF,buf,False)
    st=struct.unpack_from("<i",sb,0x40)[0]; aux=struct.unpack_from("<I",sb,0x44)[0]
    return st,aux,bytes(pay[0:64])

# CORRECT ABI: cmd_id=1 is the command GROUP, arg1 = sub-cmd (init=1000). cmd_id=2 group = user/key.
def show(tag, cmd, arg, plen=256, pre=b""):
    st,aux,pd=gf(cmd,arg,plen,pre)
    print("%-26s (cmd%d arg%d) -> status=%d aux=0x%x payload=%s"%(tag,cmd,arg,st,aux,pd[:24].hex()))
    return st

# try init BEFORE key (cmd1/arg1000)
show("INIT pre-key", 1, 1000)
# setkey (cmd2/arg109, payload=keymaster resp)
show("SETKEY", 2, 109, 256, key256)
# init after key + reinit sequence
show("INIT post-key", 1, 1000)
show("REINIT 1001", 1, 1001)
show("REINIT 1004", 1, 1004)
show("REINIT 1005", 1, 1005)
# control
show("BOGUS cmd1/arg9999", 1, 9999)

os.close(gf_fd); os.close(km_fd)
if fp_fd: os.close(fp_fd)
