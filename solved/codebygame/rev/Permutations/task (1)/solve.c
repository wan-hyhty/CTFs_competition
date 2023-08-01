#include <stdio.h>

int enc(int letter)
{
    return letter ^ 0xBAD;
}

int main(int argc, const char **argv, const char **envp)
{
    int v3;        // eax
    char flag[25]; // [rsp+20h] [rbp-90h] BYREF
    int check[25]; // [rsp+40h] [rbp-70h]

    check[0] = 1983;
    check[1] = 1963;
    check[2] = 1952;
    check[3] = 1953;
    check[4] = 1982;
    check[5] = 1973;
    check[6] = 87;
    check[7] = 70;
    check[8] = 1969;
    check[9] = 1967;
    check[10] = 80;
    check[11] = 1979;
    check[12] = 93;
    check[13] = 1979;
    check[14] = 1967;
    check[15] = 109;
    check[16] = 73;
    check[17] = 1964;
    check[18] = 72;
    check[19] = 111;
    check[20] = 1979;
    check[21] = 84;
    check[22] = 108;
    check[23] = 1966;
    check[24] = 89;
    for (int i = 0; i < 24; i++)
    {
        printf("%c", enc(enc(check[i]) - 36));
    }
}