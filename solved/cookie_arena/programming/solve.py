#!/usr/bin/python3

from pwn import *

# exe = ELF('a', checksec=False)

# context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''


                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('math-is-fun-c1df4620.dailycookie.cloud', 31176)
else:
        p = process(exe.path)

GDB()
sla(b"begin", b"y")
a = ""
while(1):
	a = p.recvuntil(b"=")[:-1].decode()
	if(a.find("Very good") != -1):
		break
	res = round(eval(a))
	# info(res)
	sl(str(res).encode('utf-8'))
	# if( p.recvline() == b""
	p.recvuntil(b"Correct!\n")

b = a[34:].split()
while(1):
	cnt = 0
	res = ""

	operations = []
	numbers = []

	for e in b:
		if e in "+-*/":
			operations.append(e)
		elif e.isdigit():
			numbers.append((e))

	info(operations)
	info( numbers)

	for i in range(0, len(operations) + len(numbers) - 1):
		if(i % 2 == 0):
			res += numbers[cnt]
		else:
			res += operations[cnt]
			cnt+=1
	res += numbers[cnt]
	info(res)
	sl(str(round(eval(str(res)))).encode('utf-8'))
	b = p.recvuntil(b"=")[:-1].decode()

p.interactive()
