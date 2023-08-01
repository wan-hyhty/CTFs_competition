#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

void print_flag() {
    char flag[256];

    FILE* flagfile = fopen("flag.txt", "r");
    if (flagfile == NULL) {
        puts("Cannot read flag.txt.");
    } else {
        fgets(flag, 256, flagfile);
        flag[strcspn(flag, "\n")] = '\0';
        puts(flag);
    }
    int v7;
    char v9;
    v7 = fgets(&v9, 60, flagfile);
    if(v7)
        printf("yes");

}
int main(){
    print_flag();
}
