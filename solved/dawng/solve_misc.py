# Chuỗi ban đầu


# Tạo một danh sách các ký tự trong chuỗi
str = "}22b468c"
list = list(str)
# Hoán đổi vị trí của các ký tự
list[0], list[1], list[2], list[3], list[4], list[5], list[6], list[7] = str[7],str[6],str[5],str[4],str[3],str[2],str[1],str[0],
# Chuyển đổi danh sách trở lại thành chuỗi
str2 = ''.join(list)

# In ra kết quả
print(str2)

# actf{st4ck_it_queue_it_a619ad974c864b22}