string = [1, 1, 2 ,3 ,3]
string = sorted(string)
count = 0
i = 0
j = len(string) - 1
target = 4
while i < j:
    if (string[i] + string[j] == target):
        count += 1
        i += 1
        j -= 1
    elif (string[i] + string[j] > target):
        j -= 1
    else:
        i += 1
print(count)