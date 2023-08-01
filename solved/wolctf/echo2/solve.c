#include <stdio.h>

int main()
{
    int v2[2];
    v2[0] = 123, v2[1] = 345;
    v2[1] = scanf("%d", v2);
    printf("%d", v2[0]);
}