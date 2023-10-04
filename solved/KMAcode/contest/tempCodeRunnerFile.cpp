#include <bits/stdc++.h>
using namespace std;
typedef long long ll;

void sapxep(int a[], int max, int pos_max, int min, int pos_min, int n)
{
    // mang toan so am
    if (max <= 0)
    {
        cout << n << endl;
        cout << pos_min << " " << n << endl;
        for (int i = n; i >= 2; i--)
        {
            cout << i << " " << i - 1 << endl;
        }
    }
    else
    {
        int cnt_max_1, cnt_max_2 = 0;
        if (max < abs(min))
        {
            while (max < abs(min))
            {
                max += max;
                cnt_max_1++;
            }
            cnt_max_2 = n;
        }
        if (min > 0)
            cout << n + cnt_max_1 + cnt_max_2 << endl;
        else
            cout << n + cnt_max_1 + cnt_max_2 - 1 << endl;
            
        for (int i = 0; i < cnt_max_1; i++)
            cout << pos_max << " " << pos_max << endl;
        for (int i = 1; i <= cnt_max_2; i++)
            cout << pos_max << " " << i << endl;
        if (min > 0)
            cout << max << " " << 1 << endl;
        for (int i = 1; i < n; i++)
        {
            cout << i << " " << i + 1 << endl;
        }
    }
}

int main()
{
    int t;
    cin >> t;
    for (int cnt_t = 0; cnt_t < t; cnt_t++)
    {
        int n;
        cin >> n;
        int a[n];
        int max = -20;
        int min = 20;
        int pos_max = 0;
        int pos_min = 0;
        for (int i = 0; i < n; i++)
        {
            cin >> a[i];
            if (a[i] > max)
            {
                max = a[i];
                pos_max = i;
            }
            if (a[i] < min)
            {
                min = a[i];
                pos_min = i;
            }
        }
        sapxep(a, max, pos_max + 1, min, pos_min + 1, n);
    }
}
