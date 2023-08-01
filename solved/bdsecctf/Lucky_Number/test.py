# for a1 in range(1, 100):
#     v3 = 0
#     while a1 >= 1:
#         v3 = 10 * v3 + a1 % 10;
#         a1 /= 10
#         a1 = round(a1)
        
#     print(str(v3))
# 20365011073
import math
a1 = 37011056302
v3 = 0
while a1 >= 1:
    v3 = 10 * v3 + a1 % 10;
    a1 /= 10
    a1 = math.floor(a1)
print(str(v3))
# print("20365011073"[::-1])