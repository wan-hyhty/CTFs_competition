# bài viết hướng dẫn sử dụng pwntools
Tất cả chạy trên terminal, máy ảo, ubutu 22.04
Đầu tiên: các bạn phải cài pip, Chạy lệnh sau để cài pip3:
```
sudo apt install python3-pip
```
Sau khi cài xong pip3, ta nhập câu lệnh dưới để cài pwntools:
```
pip install pwntools
````

# cú pháp chạy 1 file python trên terminal
```
python3 tênfile.py DEBUG
```
# các câu lệnh cơ bản
```

from pwn import *               #import framework (phải có)
r = remote('103.90.227.152', 9001)  # tên_biến = remote('tên host', cổng)

r.recv(n)                          # nhận n kí tự (n là số tự nhiên)
r.recvuntil(b'abc', drop = True, keepends = False)  # nhận cho đến khi thấy byte 'abc', 
                                                    # drop = True nghĩa là nhận cho đến 'abc' và không lấy chuỗi abc
                                                    #keepends = False, không lấy xuống dòng '\n'
r.recvline()                                        # nhận hết 1 dòng, nghĩa là nhận cho đến khi thấy '\n', có thể dùng keepends để xoá \n

r.sendafter(b'abc', nội_dung_dạng_byte)             # chờ cho đến khi thấy 'abc' sẽ gửi nội dung, 
r.sendlineafter(b'abc')                             # chờ cho đến khi thấy 'abc' sẽ gửi nội dung kèm '\n'
r.interactive()
```