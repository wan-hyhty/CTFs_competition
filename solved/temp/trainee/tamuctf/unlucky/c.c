#include <stdio.h>
#include <stdlib.h>
int main()
{
    srand(0xb62d5068);
    for (int i = 0; i < 10; i++)
    {
        printf("%d\n", rand());
    }
}