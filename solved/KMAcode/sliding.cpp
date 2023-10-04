#include <iostream>
#include <algorithm>
#include <ctime>
#include <cstdlib>
using namespace std;

int main()
{
    int num[100];
    srand(time(0));
    for (int i = 0; i < 100; i++)
        num[i] = rand() % 100;

    long long max = 0;
    int k;
    cin >> k;
    int pos = 0;

    for (int i = 0; i < 100-k; i++)
    {
        long long res = 0;
        for (int j = i; j < i + k; j++)
        {
            res += num[j];
        }
        if (res > max)
        {
            pos = i;
            max = res;
        }
    }
    cout << max << endl;
    for (int i = 0; i < k; i++)
    {
        cout << num[pos + i] << " ";
    }
}