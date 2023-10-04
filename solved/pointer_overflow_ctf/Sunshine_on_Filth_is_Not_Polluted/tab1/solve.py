#!/usr/bin/python3

from pwn import *



info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)


for i in range(5910, 10000):
        
        try:
                # p = remote('34.123.210.162',20231 )
                p = process('./re3.bin')
                sla(b'Done: ', '1')
                sla(b'Username: ', 'admin')
                sla(b'Done: ', '3')
                sla(b'code: ', f'{i}')
                p.recvline()                
        except EOFError:
                p.close()
