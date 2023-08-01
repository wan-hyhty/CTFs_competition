int[] iArr = new int[25];
      
    int i5 = 0;
    for (int i6 = 0; i6 < 8; i6++) {
        i5 += iArr[i6];
    }
    if (i5 == 877) {
        z = true;
    }
    if (iArr[13] == iArr[16] && iArr[13] == iArr[21]) {
        z2 = true;
    }
    boolean z4 = iArr[19] == (7 * (iArr[12] - iArr[13])) / 2;
    boolean z5 = iArr[13] + iArr[12] == iArr[16] + iArr[15];
    boolean z6 = ((iArr[7] + iArr[8]) + iArr[9]) - 51 == 2 * iArr[9];
    boolean z7 = iArr[8] == iArr[20];
    boolean z8 = ((iArr[10] + iArr[11]) - iArr[17]) - iArr[18] == iArr[10] - iArr[17];
    boolean z9 = iArr[20] == 51;
    boolean z10 = iArr[22] + iArr[23] == iArr[22] * 2;
    boolean z11 = iArr[9] - iArr[17] == 40;
    boolean z12 = (iArr[10] - iArr[17]) - 6 == 0;
    boolean z13 = iArr[2] - iArr[11] == 50;
    boolean z14 = iArr[24] - iArr[12] == 10;
    boolean z15 = iArr[13] + iArr[15] == 2 * iArr[14];
    if (iArr[23] == iArr[22] && 3 * iArr[23] == iArr[2]) {
        z3 = true;
    }