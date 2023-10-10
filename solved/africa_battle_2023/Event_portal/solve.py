import math

a = 4643287737560106158
b = 8241998971081357166
y = 2**64

gcd_by = math.gcd(b, y)

if a % gcd_by == 0:
    i = (a // gcd_by * pow(b // gcd_by, -1, y // gcd_by)) % (y // gcd_by)
    print(i)
else:
    print("Không tìm thấy giá trị i thỏa mãn.")