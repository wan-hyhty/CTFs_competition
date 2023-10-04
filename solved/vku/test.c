#include <stdio.h>
int part1, part2 = 0;
int FUN_00101160(char a1, int a2, int a3, int a4, int a5, int a6, int a7)
{
    int result; // eax
    part1 = 0;
    part2 = 0;
    if (!part1)
    {
        putchar(a7 | a6 | a3 | (char)a2);
        putchar(a7 | a6 | a4 | (char)a3);
        putchar(a7 | a6 | a1);
        putchar(a7 | a6 | a3 | a2 | a1);
        putchar(a7 | a6 | a5 | a4 | a2 | a1);
        part1 = 1;
    }
    if (part1)
    {
        putchar(a7 | a6 | a5 | a3 | a2 | a1);
        putchar(a7 | a6 | (char)a4);
        putchar(a7 | a6 | a1);
        putchar(a7 | a6 | a5 | (char)a3);
        putchar(a7 | a5 | a4 | a3 | a2 | a1);
        putchar(a7 | a6 | a1);
        putchar(a7 | a5 | a4 | a3 | a2 | a1);
        putchar(a7 | a6 | a4 | a3 | a1);
        putchar(a7 | a6 | a3 | a1);
        putchar(a7 | a6 | a5 | a2 | a1);
        putchar(a7 | a6 | a5 | a2 | a1);
        part2 = 1;
    }
    result = part2;
    if (part2)
    {
        putchar(a7 | a6 | a5 | a4 | a3 | a1);
        return putchar(a4 | (char)a2);
    }
    return result;
}

int main()
{
    long v26 = 0x1010101;
    long v25 = 0x2020202;
    long v24 = 0x4040404;
    long v23 = 0x8080808;
    long v22 = 0x10101010;
    long v21 = 0x20202020;
    long v20 = 0x40404040;
    long v19 = 0x80808080;
    int i, j, k, m, n, ii, jj, kk, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16;
    for (i = 0; i <= 1; ++i)
    {
        for (j = 0; j <= 1; ++j)
        {
            for (k = 0; k <= 1; ++k)
            {
                for (m = 0; m <= 1; ++m)
                {
                    for (n = 0; n <= 1; ++n)
                    {
                        for (ii = 0; ii <= 1; ++ii)
                        {
                            for (jj = 0; jj <= 1; ++jj)
                            {
                                for (kk = 0; kk <= 1; ++kk)
                                {
                                    // v26 == v25;
                                    // v25 == v24;
                                    // v24 == v23;
                                    // v23 = v20;
                                    FUN_00101160(v26, v25, v24, v23, v22, v21, v20);
                                    // (char a1, int a2, int a3, int a4, int a5, int a6, int a7)
                                    // putchar(v20 | v21 | v24 | v25);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}