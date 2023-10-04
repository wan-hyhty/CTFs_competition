import random
for i in range(1024):
    print(random.randint(0,2**32),end= " ")
print()

flag=open("flag.txt","rb").read()
for i in range(100):
    if int(input(f"guess my randomness {i}:\n"))==random.randint(0,256):
        print("Nice One keep going")
        continue
    exit(0)
print(flag)