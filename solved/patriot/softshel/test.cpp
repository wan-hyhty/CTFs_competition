#include <iostream>
using namespace std;
int cnt = 0;
void swap(int *a, int *b)
{
    int temp = *a;
    *a = *b;
    *b = temp;
}

int partition(int arr[], int low, int high)
{
    int pivot = arr[(high - low) / 2];
    int i = low + 1;

    for (int j = low + 1; j <= high; j++)
    {
        if (arr[j] < pivot)
        {
            swap(&arr[i], &arr[j]);
            i++;
        }
    }
    swap(&arr[low], &arr[i - 1]);
    return (i - 1);
}

void quickSort(int arr[], int low, int high)
{
    cnt++;
    if (low < high)
    {
        int pi = partition(arr, low, high);

        quickSort(arr, low, pi - 1);
        quickSort(arr, pi + 1, high);
    }
}

void printArray(int arr[], int size)
{
    for (int i = 0; i < size; i++)
    {
        cout << arr[i] << " ";
    }
    cout << endl;
}

void phatSinhMang(int arr[], int n)
{
    
}

int main()
{
    int arr[] = {7, 2, 1, 6, 8, 5, 3, 4};
    int size = sizeof(arr) / sizeof(arr[0]);

    cout << "Mang ban dau: ";
    printArray(arr, size);

    quickSort(arr, 0, size - 1);

    cout << "Mang sau khi sap xep: ";
    printArray(arr, size);
    cout << cnt;
    return 0;
}