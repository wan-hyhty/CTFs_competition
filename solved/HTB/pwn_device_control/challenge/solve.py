#!/usr/bin/python3

from pwn import *
# import keyboard
exe = ELF('device_control_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe
# context.terminal = ['Ubuntu-22.04', '-x', 'bash', '-c']
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
        p = remote('94.237.50.62', 54446)
else:
        p = process(exe.path)

GDB()
up = "^[OA"
down = "^[OB"

def option1(slot, name, ip):
        sl(down)
        sla(b"Slot:", slot)
        sla(b"name:", name)
        sla(b"IP:", ip)
        sla(b"continue.", "")
        p.interactive()
def option4(slot, payload):
        s("^[[B".encode('utf-8'))
        # sla(b"Slot:", slot)
        # sla(b"country:", payload)
        # sla(b"continue.", "")

        
# sa(b"Exit","aaaaaaaa")

# option1("0", "a", "111111111")
# # sleep(3)
# option4("0", "%p%p%p%p%p%p%p%p%p%p%p%p%p%p")
# # option1(b"1", b"a", b"1")
p.interactive()

