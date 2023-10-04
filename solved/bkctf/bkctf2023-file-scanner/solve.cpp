#include <iostream>
#include <algorithm>

using namespace std;

int timkiemtt(int a[], int n, int x)
{
    for (int i = 0; i < n; i++)
    {
        if (a[i] == x)
            return i;
    }
    return -1;
}

int timkiemnp(int a[], int n, int x)
{
    int l = 0;
    int r = n;
    int m = (r - l) / 2;
    while (l < r)
    {
        if (a[m] == x)
            return m;
        else if (a[m] < x)
        {
            l = m + 1;
        }
        else
        {
            l = m - 1;
        }
        m = (r - l) / 2;
    }
    return -1;
}

int main()
{
    int a[1000];
    int x, n;
    cin >> n >> x;
    for (int i = 0; i < n; i++)
    {
        cin >> a[i];
    }

    sort(a, a + n);

    cout << timkiemtt(a, n, x);
    cout << timkiemnp(a, n, x);
}