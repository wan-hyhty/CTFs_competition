#include <stdio.h>

int main()
{
    char flag[29]; // [rsp+20h] [rbp-60h] BYREF
    int data[29];  // [rsp+40h] [rbp-40h]
    int ar[29];    // [rsp+C0h] [rbp+40h]
    int i;         // [rsp+13Ch] [rbp+BCh]

    ar[0] = 22;
    ar[1] = 28;
    ar[2] = 0;
    ar[3] = 14;
    ar[4] = 1;
    ar[5] = 16;
    ar[6] = 20;
    ar[7] = 4;
    ar[8] = 25;
    ar[9] = 17;
    ar[10] = 24;
    ar[11] = 23;
    ar[12] = 19;
    ar[13] = 6;
    ar[14] = 13;
    ar[15] = 9;
    ar[16] = 8;
    ar[17] = 10;
    ar[18] = 21;
    ar[19] = 26;
    ar[20] = 12;
    ar[21] = 27;
    ar[22] = 15;
    ar[23] = 2;
    ar[24] = 5;
    ar[25] = 11;
    ar[26] = 18;
    ar[27] = 3;
    ar[28] = 7;
    data[0] = 51;
    data[1] = 125;
    data[2] = 67;
    data[3] = 114;
    data[4] = 79;
    data[5] = 51;
    data[6] = 49;
    data[7] = 66;
    data[8] = 48;
    data[9] = 114;
    data[10] = 119;
    data[11] = 95;
    data[12] = 110;
    data[13] = 123;
    data[14] = 97;
    data[15] = 114;
    data[16] = 48;
    data[17] = 51;
    data[18] = 99;
    data[19] = 114;
    data[20] = 104;
    data[21] = 107;
    data[22] = 100;
    data[23] = 68;
    data[24] = 89;
    data[25] = 95;
    data[26] = 95;
    data[27] = 69;
    data[28] = 109;
    puts("ENTER FLAG: ");
    
      for ( i = 0; i <= 28; ++i )
      {
            flag[ar[i]] = data[i];
      }
    printf("%s", flag);
    return 0;
}

// CO____________r_______3_____}
// 01234567890123456789012345678