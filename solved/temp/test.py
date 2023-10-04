from pwn import *
while(1):
	p = remote("0.tcp.ap.ngrok.io", 17385)
	p.close()
