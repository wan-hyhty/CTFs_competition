#include <stdio.h>
#include <string.h>
#include <stdlib.h>
long exit_code = 0x68732f6e69622f;
void exit_f()
{
    asm("mov %%rax, %0" ::"r"(&exit_code));
    asm("mov %rax, %rdi");
    asm("call exit");
}

void init()
{
    setbuf(stdin, 0);
    setbuf(stderr, 0);
    setbuf(stdout, 0);
}

void win()
{
    system("cat fmt");
}

void fmt()
{
    while (1)
    {
        char payload[0x40];
        puts("den duoc day r ak");
        puts("phai lam gi day?????");
        fgets(payload, 0x18, stdin);
        printf(payload);
        printf("\n");
        if (strlen(payload) > 11)
            break;
    }
    puts("end");
    asm("xor %rax, %rax");
    asm("mov %%rax, +0x10(%%rbp)" ::);
    asm("mov %%rax, +0x18(%%rbp)" ::);
}
int main()
{
    init();
    char payload[0x40];
    puts("ret2win or fmt");
    read(0, payload, 0x10);
    printf(payload);
    puts("8==D");
    read(0, payload, 0x50);
    asm("xor %rax, %rax");
    asm("mov %%rax, +0x10(%%rbp)" ::);
    asm("mov %%rax, +0x18(%%rbp)" ::);
    // asm("mov %%rax, %0" ::"r"(&sub_1337 + 19));
    // asm("mov +0x8(%%rbp), %%rbx"
    //     :
    //     :);
    // asm("cmp %rax, %rbx\n\t"
    //     "jne label1\n\t"
    //     "label2:\n\t");
    // asm("movq $0x3c, %%rax" ::);
    // asm("xor %rdi, %rdi\n\t"
    //     "syscall\n\t"
    //     "ret\n"
    //     "jmp label2\n\t"
    //     "label1:\n\t"
    //     "leave\n"
    //     "nop\n"
    //     "ret");
}