#include <iostream>
#include <algorithm>
#include <ctime>
#include <cstdlib>
#include <queue>

int n, m;
int a[105][105];
int dx[] = {0, 1, 0, -1};
int dy[] = {1, 0, -1, 0};
using namespace std;
queue<int> qx;
queue<int> qy;

int bfs(int u, int v)
{
    int x1, y1, count = 0;
    while (qx.size())
    {
        int size = qx.size();
        for (int k = 0; k < size; k++)
        {
            for (int i = 0; i < 4; i++)
            {
                x1 = qx.front() + dx[i];
                y1 = qy.front() + dy[i];
                if (x1 == u && y1 == v)
                    return count+1;
                if (x1 >= 0 && y1 >= 0 && x1 < n && y1 < m && a[x1][y1])
                {
                    qx.push(x1);
                    qy.push(y1);
                }
            }
            a[qx.front()][qy.front()] = 0;
            qx.pop();
            qy.pop();
        }
        count++;
    }
    return -1;
}

int main()
{
    int s, t, u, v;
    cin >> n >> m >> s >> t >> u >> v;
    --s, --t, --u, --v;
    for (int i = 0; i < n; i++)
        for (int j = 0; j < m; j++)
            cin >> a[i][j];
    qx.push(s);
    qy.push(t);
    cout << bfs(u, v);
}