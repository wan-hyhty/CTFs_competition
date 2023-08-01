#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void win(){
    FILE *fp = fopen("./flag.txt", "r");
    if(fp == NULL) {printf("try on a remote server\n"); exit(1);}
    char flag[30];
    fgets(flag, 26, fp);
    fclose(fp);
    printf("%s\n", flag);
    exit(0);
}

int check(char *s){
    int cnt = 0;
    int ret = 0;
    for(int i=0; i<64; i++){
        if(s[i] & (char)(32)) cnt++;
        ret++;    
    }
    
    asm volatile(
        "movl -4(%rbp), %eax\n\t"
        "andl $0x20, %eax\n\t"
        "movl %eax, -8(%rbp)\n\t"
        "nop\n\t"
    );

    return ret;
}

void play_with_buf(char *buf, int i){

    if(i>=80) return;

    asm volatile(
        "pushq %rdx\n\t"
        "pushq %rax\n\t"
        "xorq %rdx, %rdx\n\t"
        "orl  $0x20, %edx\n\t"
        "shl  $0x8,  %edx\n\t"
        "orl  $0x20, %edx\n\t"
        "shl  $0x8,  %edx\n\t"
        "orl  $0x20, %edx\n\t"
        "shl  $0x8,  %edx\n\t"
        "orl  $0x20, %edx\n\t"
    );

    asm volatile(
        "movl (%rdi, %rsi, 1), %eax\n\t"
        "xorl %edx, %eax\n\t"
        "movl %eax, (%rdi, %rsi, 1)\n\t"
        "popq %rax\n\t"
        "popq %rdx\n\t"
    );

    play_with_buf(buf, (i+4));
}


int main(){

    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    char buf[64];
    memset(buf, 0x20, sizeof(buf));
    printf("%p\n", &win);
    gets(buf);
    play_with_buf(buf,0);

    if(check(buf)){
        printf("good try :)\n");
        return 0;
    }
    else {
        printf("ooooopsss\n");
        exit(0);
    }
}
