key = 2
flag = ''
dât 
for i in data:
    flag = flag + chr(ord(i)+key)
    key = key + 1
print(flag)
