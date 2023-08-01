from pwn import *
import pickle
p = process(
    'ncat --ssl pickle-trouble-2eddfdefdc91cd01.chall.ctf.blackpinker.com 443'.split())
payload1 = 123
p.sendafter(b"(send as byte string)\n", str(payload1))
data = {"name": "John", "age": 30}
pickle_data = pickle.dumps(data)
self.request.sendall(pickle_data)


p.interactive()
