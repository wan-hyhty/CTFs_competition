#include <iostream>
#include <cmath>
using namespace std;

int main()
{
    int t;
    cin >> t;

    for (int cnt_t = 0; cnt_t < t; cnt_t++)
    {
        int n;
        cin >> n;
        int a[n + 5];
        for (int cnt_n = 0; cnt_n < n; cnt_n++)
            cin >> a[cnt_n];
        int count = 0;
        for (int i = 0; i < n; i++)
        {
            if (i + 1 == a[i])
            {
                count++;
            }
        }
        cout << round((double)count / 2) << endl;
    }
}