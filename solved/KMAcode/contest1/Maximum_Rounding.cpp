#include <iostream>
using namespace std;
int MAX_LINE = 200000 + 5;
int main()
{
    int t;
    cin >> t;
    cin.ignore();
    while (t--)
    {
        char s[MAX_LINE];
        cin.getline((s + 1), MAX_LINE);
        s[0] = '0';
        int pos = -1;
        int du = 0;

        for (int i = 0; i < strlen(s); i++)
        {
            if (s[i] >= '5')
            {
                pos = i;
                break;
            }
        }

        if(s[pos] == '9')
        {
            du += 1;
        }

        if (pos > -1)
        {
            s[pos] += 1;
        }

        if (s[0] == '0')
            cout << (s + 1);
        else
            cout << s;
        cout << endl;
    }
}