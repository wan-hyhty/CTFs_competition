import math
string = 'T8P1V5ExmPLxIurhx2Sth2LwK812Uc23iYCKSwAYBDvqRrsCMce4lU7003md6P7I'
dictionary = {}
for char in string:
    if( char in dictionary.keys()):
        dictionary[char] += 1
    else:
        dictionary[char]=1
for char in dictionary:
    if dictionary[char] > 1:
        print(char,' -> ',dictionary[char])

tu = int(math.factorial(len(string)))
mau = 1
for char in dictionary:
    mau *= int(math.factorial(dictionary[char]))
res = int(tu) // int(mau)
print((res))
    
    
        
