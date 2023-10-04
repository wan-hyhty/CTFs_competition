#!/usr/bin/python3

from pwn import *

exe = ELF('re31.bin', checksec=False)

context.binary = exe

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

file = open("log.txt", "a")

for i in range(123, 10000//2):
        p = remote('34.123.210.162',20231 )
        sla(b'Done: ', '1')
        sla(b'Username: ', b'admin')
        sla(b'Done: ', '3')
        sla(b'code: ', f'{i}')
        print(i)
        response = p.recvline()
        file.write(str(response) + f"{i}\n")
        p.close()
p.interactive()
