#include <iostream>
#include <cmath>
using namespace std;

int main()
{
    int t;
    cin >> t;
    for (int j = 0; j < t; j++)
    {
        long long n;
        cin >> n;
        int cnt = 0;
        int max = 0;
        for (long long i = 1; i <= n; i++)
        {
            if (n % i == 0)
                cnt++;
            else
                break;
        }
        if (n == 1)
            cout << 1 << endl;
        else
            cout << cnt << endl;
    }
}