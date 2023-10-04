def manipulate(input_str):
    SZ = len(input_str)
    B1, B2, K = 131, 13, 10**9 + 7
    fh, fs, pw1, pw2 = [0] * SZ, [0] * SZ, [1], [1]

    for i in range(SZ):
        pw1.append(pw1[-1] * B1 % K)
        pw2.append(pw2[-1] * B2 % K)
        fh[i] = (fh[i-1] * B1 + ord(input_str[i])) % K
        fs[i] = (fs[i-1] * B2 + ord(input_str[i])) % K

    f = (fh[SZ-1] - fh[0] * pw1[SZ-1] % K + K) % K
    s = (fs[SZ-1] - fs[0] * pw2[SZ-1] % K + K) % K
    return (f << 31) ^ s

# while True:
print("Error. Login Required.")
print("Please enter the corresponding passcodesto proceed.")
with open('primes.txt', 'r') as file:
    content = file.read()

numbers = [int(num) for num in content.split()]
token_list = []
# for i in range(0, 600-3):
c = 18446744073709551437
d = 18446744073709551521
a = 18446744073709551533
b = 18446744073709551557

x = manipulate(str(a))
y = manipulate(str(b))
z = manipulate(str(c))
w = manipulate(str(d))

token = manipulate(str(x + y + z + w))
token_list.append("ctf{" + str(token) + "}")
print(token_list)

# with open('res.txt', 'w') as res:
#     for i in range(0, 600-3):
#         res.write(str(numbers[i]) + "\n" + token_list[i] + "\n") 
#         # res.close()   
# print(token_list)
