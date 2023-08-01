with open('rockyou.txt', 'r') as input_file, open('word.txt', 'w') as output_file:
    while True:
        # Đọc nội dung của file đầu vào
        content = input_file.readline()
        # Ghi nội dung vào file đầu ra
        output_file.write("HCMUS-CTF{" + content[:-1] + "}\n")
