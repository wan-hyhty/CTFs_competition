from pwn import *
import math
r = remote("103.90.227.152", 9004)
r.recvlines(8)
for j in range(0, 65):
    r.recvuntil(b"S = ")
    string = r.recvline(keepends = False).decode()
    res = {}
    for char in string:
        if( char in res.keys()):
            res[char] += 1
        else:
            res[char]=1
    tu = int(math.factorial(len(string)))
    mau = 1
    for char in res:
        mau *= int(math.factorial(res[char]))

    r.sendafter(b'answer = ', str(tu // mau).encode())
r.interactive()
#KCSC{Amazingg ! Were you good at math in high school?}