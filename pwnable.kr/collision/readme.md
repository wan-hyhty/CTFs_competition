# collision

## Phân tích

- `argv[1]` của chúng ta là char

```c
unsigned long check_password(const char* p){
        int* ip = (int*)p;
        int i;
        int res=0;
        for(i=0; i<5; i++){
                res += ip[i];
        }
        return res;
}
```
- Ép kiểu `argv` sang int và cộng vào res sao cho bằng `0x21DD09EC`
- Do 1 phần tử của int là 4 byte nên từ chuỗi `argv` chia ra 5 phần và cộng lại với nhay

## Khai thác

```
>>> hex(0x6c5cec8* 4 + 0x6c5cecc)
'0x21dd09ec'
```

```python
from pwn import *

server = ssh('col', 'pwnable.kr', 2222, 'guest')
shell = server.process(['./col', p32(0x6c5cec8) * 4 + p32(0x6c5cecc)])
result = shell.recvall()
shell.close()
server.close()

print("Flag: {}".format(result.decode("utf-8")))

```
```
[DEBUG] Received 0x34 bytes:
    b'daddy! I just managed to create a hash collision :)\n'
```