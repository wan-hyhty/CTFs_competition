#!/usr/bin/python3

from pwn import *

exe = ELF('re31.bin', checksec=False)

context.binary = exe

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)


l = 10000//2
r = 10000
m = (r-l) //2
for i in range(l, r):
        p = remote('34.123.210.162',20231 )
        sla(b'Done: ', '1')
        sla(b'Username: ', b'admin')
        sla(b'Done: ', '3')
        sla(b'code: ', f'{i}')
        print(i)
        try:
                sla(b'denied\n', 'ls')
                response = p.recvline()
                print(response)
        except EOFError:
                print(f"Received EOF from remote. Closing connection.{i}")
                p.close()
p.interactive()
