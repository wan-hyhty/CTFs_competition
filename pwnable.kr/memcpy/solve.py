#!/usr/bin/python3

from pwn import *


def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''


                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('pwnable.kr', 9022)
else:
        p = process(exe.path)

GDB()
p.recvlines(9)
for i in range(1, 11):
        sla(b":", str(8*i))
        sleep(4)
p.interactive()
"""
experiment 1 : memcpy with buffer size 8
ellapsed CPU cycles for slow_memcpy : 2128
ellapsed CPU cycles for fast_memcpy : 246

experiment 2 : memcpy with buffer size 16
ellapsed CPU cycles for slow_memcpy : 330
ellapsed CPU cycles for fast_memcpy : 192

experiment 3 : memcpy with buffer size 32
ellapsed CPU cycles for slow_memcpy : 406
ellapsed CPU cycles for fast_memcpy : 336

experiment 4 : memcpy with buffer size 72
ellapsed CPU cycles for slow_memcpy : 648
ellapsed CPU cycles for fast_memcpy : 212

experiment 5 : memcpy with buffer size 136
ellapsed CPU cycles for slow_memcpy : 1020
ellapsed CPU cycles for fast_memcpy : 188

experiment 6 : memcpy with buffer size 264
ellapsed CPU cycles for slow_memcpy : 2010
ellapsed CPU cycles for fast_memcpy : 204

experiment 7 : memcpy with buffer size 520
ellapsed CPU cycles for slow_memcpy : 3740
ellapsed CPU cycles for fast_memcpy : 280

experiment 8 : memcpy with buffer size 1032
ellapsed CPU cycles for slow_memcpy : 7294
ellapsed CPU cycles for fast_memcpy : 504

experiment 9 : memcpy with buffer size 2056
ellapsed CPU cycles for slow_memcpy : 14436
ellapsed CPU cycles for fast_memcpy : 754

experiment 10 : memcpy with buffer size 5004
ellapsed CPU cycles for slow_memcpy : 37792
ellapsed CPU cycles for fast_memcpy : 2094

thanks for helping my experiment!
flag : 1_w4nn4_br34K_th3_m3m0ry_4lignm3nt
"""