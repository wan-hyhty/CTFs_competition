#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void get_str(char* buffer, unsigned int length) {
    int size;
    
    size = read(0, buffer, length - 1);
    if (buffer[size - 1] == '\n') {
        buffer[size - 1] = '\0';
    }
}

int filter(char* input, unsigned int length) {
    if (input == NULL) {
        return 0;
    }

    if (length == 0) {
        return 0;
    }

    for (int i = 0; i < length; i++) {
        if (input[i] >= '0' && input[i] <= '9') {
            continue;
        }

        if (input[i] == '%' || input[i] == 'c' || input[i] == 'n' || input[i] == 'h' || input[i] == '$') {
            continue;
        }

        if (input[i] == '\0') {
            break;
        }

        return 0;
    }

    return 1;
}

int main() {
    FILE* fd = fopen("./flag.txt", "r");
    char format[0x10];
    char flag[0x30];

    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);
    setvbuf(stderr, 0, _IONBF, 0);

    if (fd == NULL) {
        return -1;
    }

    printf("My stack: %p\n", format);
    memset(flag, 0, sizeof(flag));
    fgets(flag, sizeof(flag), fd);

    while (1) {
        printf("Your format: ");
        get_str(format, sizeof(format));
        if (!filter(format, sizeof(format) - 1)) {
            exit(-1);
        }

        printf(format);
    }

    return 0;    
}