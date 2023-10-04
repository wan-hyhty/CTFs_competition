from pwn import *
import hashlib
import subprocess

def md5sum(b: bytes):
    return hashlib.md5(b).digest()[:3]


whitelisted_cmd = b'echo lmao'
whitelisted_hash = md5sum(whitelisted_cmd)
print(whitelisted_hash)
for i in range(2**32):
    if whitelisted_hash == md5sum((f"echo {i:010} | cat flag.txt").encode()):
        cmd = (f"echo {i:010} | cat flag.txt").encode()
        print(cmd)
        break

p = remote("tamuctf.com", 443, ssl=True, sni="md5")
p.sendline(cmd)
p.interactive()
