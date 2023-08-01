#include <stdio.h>

int main()
{
    int i;
    int a1 = 0;
    for (i = 1; (i & a1) == 0; i *= 2)
    {
        a1 ^= i;
        printf("%d", a1);
    }
    printf("%d", i ^ a1);
}