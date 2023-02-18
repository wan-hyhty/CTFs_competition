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
