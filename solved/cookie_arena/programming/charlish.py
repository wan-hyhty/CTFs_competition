nguyen_am = ['a', 'e', 'i', 'o', 'u']
khong_lam_gi = 0

for j in range (6):
    check = 1
    user = input() + "n"
    for i in range(0, len(user) - 1):
        if user[i] == "n":
            khong_lam_gi = 0
        elif user[i] not in nguyen_am and user[i+1] not in nguyen_am:
            check = 0
            break          
    if check == 0:
        print("No")
    else:
        print("Yes")
            