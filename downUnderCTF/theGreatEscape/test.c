#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
int main()
{
    char test[0x100];
    int dir_fd = openat(AT_FDCWD, "chal", O_RDONLY);
    openat(dir_fd, "flag.txt",2);
    // open("/chal/flag.txt", 'r');
    read(4, test, 0x100);
}