from pwn import *

r = remote('103.90.227.152', 9003)


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