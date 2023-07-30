import string
def enc(b):
    a = b[0]*2**24+b[1]*2**16+b[2]*2**8+b[3]+1
    tmp = 0 
    for i in range(50):
        if 2 ** i < a and 2 ** (i+1) > a:
            tmp = 2 ** i
            break 
    s = (a - tmp) * 2 - 1
    return s

print(bytes.fromhex(hex(enc(list('ictf'.encode())[::-1]))[2:].zfill(8)))
#     for x in string.printable:
#         for y in string.printable:
#             for z in string.printable:
#                 for t in string.printable:
#                     f.write(str(bytes.fromhex(hex(enc(list((x + y + z + t).encode())[::-1]))[2:].zfill(8))) + "\n")
# print(bytes.fromhex(hex(enc(list("ictf".encode())[::-1]))[2:].zfill))
# L\xe8\xc6\xd2
# f\xde\xd4\xf6
# j\xd0\xe0\xca
# d\xe0\xbe\xe6
# J\xd8\xc4\xde
# `\xe6\xbe\xda
# >\xc8\xca\xca
# ^\xde\xde\xc4
# ^\xde\xde\xde
# z\xe8\xe6\xde
with open("res2.txt", "w") as f:
    for x in string.printable:
        for y in string.printable:
        
            f.write(x + " "+ y + "\n")
            f.write(str(bytes.fromhex(hex(enc(list(("aa"+ x+ y).encode())[::-1]))[2:].zfill(8))) + "\n")
        
    