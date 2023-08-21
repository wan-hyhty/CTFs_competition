from pwn import *

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                c
                ''')
                raw_input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('pwnable.kr', 9007)
else:
        p = process(exe.path)

GDB()
p.recvuntil("3 sec... -\n\t\n")

for k in range(100):
        N = int(p.recvuntil(" ", drop=True)[2:])
        C = int(p.recvuntil("\n")[2:])
        info("N=%d C=%d" % (N, C))
        mid = int(round(N/2))
        left = 0
        right = N
        for _ in range(C):
                print left
                print right
                print mid
                for i in xrange(left, mid):
                        s(str(i) + " ")
                s("\n")
                res = int(p.recvline())
                info("res: %d" % res)
                if res == 10 * (mid - left):
                        left = mid
                        mid = left + int(round((right-left)/2))
                else:
                        right = mid
                        mid = mid - int(round((right-left)/2))
        sl(str(left))
        print p.recvline()

p.interactive()