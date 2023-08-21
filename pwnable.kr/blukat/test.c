#include <stdio.h>
#include <string.h>
int main()
{
    printf("%d", strcmp("a", "\0"));
}