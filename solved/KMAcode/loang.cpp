#include <iostream>
#include <algorithm>
#include <ctime>
#include <cstdlib>

int dx[4] = {-1, 0, 0, 1};
int dy[4] = {0, -1, -1, 0};
int a[100][100];
int n;
void loang(int i, int j)
{
    a[i][j] = 0;
    for(int k = 0; k < 4; k)
    {
        int i1 = i + dx[k];
        int j1 = j + dy[k];
        if(i1 >=0 && i1 < n && j1 >= 0 && j1 < n && a[i1][j1])
        {
            loang(i1, j1);
        }
    }
}