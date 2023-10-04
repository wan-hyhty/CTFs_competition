// #include <iostream>
// #include <cmath>
// using namespace std;
// typedef long long ll;

// void sapxep(int num, int max, int pos_max, int min, int pos_min, int n)
// {
//     int cnt_max_1 = 0;
//     if (max <= 0)
//     {
//         cout << n << endl;
//         cout << pos_min << " " << n << endl;
//         for (int i = n; i >= 2; i--)
//         {
//             cout << i << " " << i - 1 << endl;
//         }
//     }
//     else
//     {

//         if (max < abs(min))
//         {
//             while (max < abs(min))
//             {
//                 max += max;
//                 cnt_max_1++;
//             }
//         }
//         cout << n + cnt_max_1 + n - 1 << endl;

//         for (int i = 0; i < cnt_max_1; i++)
//             cout << pos_max << " " << pos_max << endl;
//         for (int j = 1; j <= n; j++)
//             cout << pos_max << " " << j << endl;
//         for (int i = 1; i < n; i++)
//         {
//             cout << i << " " << i + 1 << endl;
//         }
//     }
// }

// int main()
// {
//     int t;
//     cin >> t;
//     for (int cnt_t = 0; cnt_t < t; cnt_t++)
//     {
//         int n;
//         cin >> n;
//         int num;
//         int max = -20;
//         int min = 20;
//         int pos_max = 0;
//         int pos_min = 0;
//         for (int i = 0; i < n; i++)
//         {
//             cin >> num;
//             if (num > max)
//             {
//                 max = num;
//                 pos_max = i;
//             }
//             else if (num <= min)
//             {
//                 min = num;
//                 pos_min = i;
//             }
//         }
//         sapxep(num, max, pos_max + 1, min, pos_min + 1, n);
//     }
// }

#include <bits/stdc++.h>
using namespace std;
typedef long long ll;
int main()
{
    int t;
    cin >> t;
    while (t--)
    {
        ll n;
        cin >> n;
        vector<int> v;
        int hi = -20, ph = 0, lo = 20;
        for (ll i = 1; i <= n; i++)
        {
            int a;
            cin >> a;
            if (a > hi)
            {
                hi = a;
                ph = i;
            }
            if (a < lo)
            {
                lo = a;
            }
            v.push_back(a);
        }
        int c = 0, b = 0;
        if (hi <= 0)
        {
            cout << n - 1 << endl;
            for (int i = n; i > 1; i--)
                cout << i - 1 << " " << i << endl;
        }
        else
        {
            if (hi < abs(lo))
            {
                while (hi < abs(lo))
                {
                    hi += hi;
                    c++;
                }
            }
            b = c + n + n - 1;
            cout << b << endl;
            for (int i = 0; i < c; i++)
                cout << ph << " " << ph << endl;
            for (int i = 1; i <= n; i++)
                cout << i << " " << ph << endl;
            for (int i = 1; i < n; i++)
                cout << i + 1 << " " << i << endl;
        }
    }
}