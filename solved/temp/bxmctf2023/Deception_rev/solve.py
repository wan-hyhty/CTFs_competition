import subprocess

# Tên file Java cần chạy
filename = "Deception"
res = []
# Nhập dữ liệu từ bàn phím
for i in range(500, 600):
    input_str = str(i)
# Chạy file Java
    process = subprocess.Popen(
        ["java", filename], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Gửi dữ liệu đầu vào vào quá trình Java
    out, err = process.communicate(input_str.encode())
    res.append(out.decode())
    print(f"{i}" + out.decode())

# print(res.count())
# In kết quả đầu ra
