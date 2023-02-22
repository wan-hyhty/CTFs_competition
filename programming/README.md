# chall 1
<details> <summary> script </summary>

  ```python
from pwn import *
r = remote('103.90.227.152', 9001)
from functools import lru_cache
import sys
sys.setrecursionlimit(5000)
@lru_cache()

def fi(n):
    if n == 1 or n == 2:
        return 1
    return fi(n - 1) + fi(n - 2)

r.recvuntil(b'Answer = 34\n')
for j in range (1, 65):
     r.recvuntil(b'N = ')
     n = r.recvline(keepends = False)
     res = str(fi(int(n)))
     r.sendlineafter(b'Answer = ', res.encode())
r.interactive()
#KCSC{Old_buT_g0ld}
  ```
  
</details>

# chall 2
<details> <summary> script </summary>
  
  ```python
  from pwn import *
r = remote('103.90.227.152', 9002)

r.recvlines(4)
for j in range(0, 65):
    r.recvuntil(b'arr = [')
    tmp = r.recvline().decode()
    arr = tmp[:-2].replace(",", "").split()   
    res = 1
    
    print(arr)
    for i in range(0, len(arr)):
        res *= int(arr[i])
    r.sendlineafter(b'answer = ', str(res).encode())
r.interactive()
#KCSC{y0u_s0_G0od_at_ProGraMm1n9}
  ```
  
</details>

# chall 3
<details> <summary> script </summary>
  
  ```python
  from pwn import *

r = remote('103.90.227.152', 9003)

for k  in range (0, 65):
    r.recvuntil(b'ciphertext = ')
    cipher = r.recvline(keepends=False).decode()
    len_cipher = len(cipher)
    res = ""
    i = 0
    
    while i < len_cipher:
        if (int(cipher[i]) < 2):
            tmp = cipher[i] + cipher[i+1] + cipher[i+2]
            res += tmp
            i += 3
        else:
            res += cipher[i] + cipher[i+1]
            i += 2
        res += " "
    
    res = res.split()
    plain = ""
    
    for i in range(0, len(res)):
        plain += chr(int(res[i]))
    r.sendlineafter(b'plaintext = ', plain)
r.interactive()
#KCSC{Fact : It's RickRoll's lyrics}
  ```
  
  </details>
  
  # chall 4
  <details> <summary> script </summary>
  
  ```python
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
  ```
  
  </details>
  
# chall 5
  <details> <summary> script </summary>
  
  ```python
  
  from pwn import *

r = remote("103.90.227.152", 9005)

r.recvlines(10)
for l in range(0, 64):
    r.recvuntil(b"Nums = [")
    string = r.recvline(keepends=False)[:-1].decode().replace(",", "").split()
    string = list(map(int, string))
    string = sorted(string)
    print(string)
    r.recvuntil(b"Target = ")
    target = int(r.recvline(keepends=False), 10)

    count = 0
    i = 0
    j = len(string) - 1

    while i < j:
        if (string[i] + string[j] == target):
            count += 1
            i += 1
            j -= 1
        elif (string[i] + string[j] > target):
            j -= 1
        else:
            i += 1

    r.sendafter(b'Answer = ', str(count).encode())
r.interactive()
#KCSC{Before_you_learn_hacking_you_should_learn_programming}
  
  ```
  
   </details>
  
