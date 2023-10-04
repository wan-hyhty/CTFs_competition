
flag = "12h, 11h, 0, 15h, 0Bh, 48h, 3Ch, 12h, 0Ch, 44h, 0, 10h, 51h, 19h, 2Eh, 16h, 3, 1Ch, 42h, 11h, 0Ah, 4Ah, 72h, 56h, 0Dh, 7Ah, 74h, 4Fh, 0"
flag = flag.replace(",", "")
flag = flag.replace("h", "")
flag = flag.split()
for i in range(0, len(flag)):
    flag[i] = "0x" + flag[i]
str = "tjct"
for i in range(0, 28):
    temp = chr(ord(str[i]) ^ int(flag[i], 16))
    str += temp
print(str)
# print(flag)
