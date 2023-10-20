from pwn import *
import ctypes
exe = ELF('challenge', checksec=False)
libc = ctypes.CDLL('/usr/lib/x86_64-linux-gnu/libc.so.6')
libc.srand(1697247726)
print(str(libc.rand()))