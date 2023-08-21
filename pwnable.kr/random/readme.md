# random
## Phân tích
- Lỗi ở đây là do `srand()` một hằng số (srand() không được gọi nên không sinh bộ số cho rand())
- Do đó rand() không random

## Khai thác
- Có nhiều cách khai thác, ở đây do rand() không random nên mình bật debug trên server và lấy giá trị rand trả về

```
RAX: 0x6b8b4567  <-- giá trị của rand()
RBX: 0x0
RCX: 0x7f5df93680a4 --> 0x16a5bce3991539b1
RDX: 0x7f5df93680a8 --> 0x6774a4cd16a5bce3
RSI: 0x7ffd2f3b5b7c --> 0x6b8b4567
RDI: 0x7f5df9368620 --> 0x7f5df93680b4 --> 0x61048c054e508aaa
RBP: 0x7ffd2f3b5bb0 --> 0x400670 (<__libc_csu_init>:    mov    QWORD PTR [rsp-0x28],rbp)
RSP: 0x7ffd2f3b5ba0 --> 0x7ffd2f3b5c90 --> 0x1
RIP: 0x400606 (<main+18>:       mov    DWORD PTR [rbp-0x4],eax)
R8 : 0x7f5df93680a4 --> 0x16a5bce3991539b1
R9 : 0x7f5df9368120 --> 0x8
R10: 0x47f
R11: 0x7f5df8fdef70 (<rand>:    sub    rsp,0x8)
R12: 0x400510 (<_start>:        xor    ebp,ebp)
R13: 0x7ffd2f3b5c90 --> 0x1
R14: 0x0
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x4005f8 <main+4>:   sub    rsp,0x10
   0x4005fc <main+8>:   mov    eax,0x0
   0x400601 <main+13>:  call   0x400500 <rand@plt>
=> 0x400606 <main+18>:  mov    DWORD PTR [rbp-0x4],eax
   0x400609 <main+21>:  mov    DWORD PTR [rbp-0x8],0x0
   0x400610 <main+28>:  mov    eax,0x400760
   0x400615 <main+33>:  lea    rdx,[rbp-0x8]
   0x400619 <main+37>:  mov    rsi,rdx
```

```
>>> 0x6b8b4567 ^ 0xdeadbeef
3039230856
```

```
random@pwnable:~$ ./random
3039230856
Good!
Mommy, I thought libc random is unpredictable...
```