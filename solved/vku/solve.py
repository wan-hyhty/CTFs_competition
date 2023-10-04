#!/usr/bin/python3

from pwn import *

exe = ELF('moonshot_bin', checksec=False)

kk = 1
jj = 1
ii = 1
n = 1
m = 1
k = 1
j = 1
i = 1


context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript=f'''

                set $rbp-0x20={kk} 
                set $rbp-0x1C={jj} 
                set $rbp-0x18={ii} 
                set $rbp-0x14={n} 
                set $rbp-0x10={m}
                set $rbp-0xC ={k} 
                set $rbp-0x8 ={j} 
                set $rbp-0x4 ={i} 
                b*main+464
                b*main+308
                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('')
else:
        p = process(exe.path)
# gdb.attach(p,gdbscript='''
#            b*main+308
#            b*main+464
#            ''')
# input()
# sla(b"...\n", str(0))

GDB()
# sla(b"...\n", str(0))

p.interactive()

# int v18; rbp-48h BYREF
# int v19; rbp-44h
# int v20; rbp-40h
# int v21; rbp-3Ch
# int v22; rbp-38h
# int v23; rbp-34h
# int v24; rbp-30h
# int v25; rbp-2Ch
# int v26; rbp-28h
# int v27; rbp-24h
# int kk;  rbp-20h
# int jj;  rbp-1Ch
# int ii;  rbp-18h
# int n;   rbp-14h
# int m;   rbp-10h
# int k;   rbp-Ch
# int j;   rbp-8h
# int i;   rbp-4h