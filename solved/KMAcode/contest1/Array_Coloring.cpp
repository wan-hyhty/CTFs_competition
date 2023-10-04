#include <iostream>

using namespace std;

int main()
{
    int t;
    cin >> t;
    while (t--)
    {
        int cnt=0;
        int n;
        cin >> n;
        int a;
        for (int i = 0; i < n; i++)
        {
            cin >> a;
            if (a % 2 == 1)
                cnt++;
        }
        if (cnt % 2 == 1)

            cout << "NO\n";
        else
            cout << "YES\n";
    }
}