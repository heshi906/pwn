from pwn import *
p = remote("0.0.0.0",38073)
for i in range(100):
    p.recvuntil("The second:")
    p.recvline()
    first =p.recvuntil("+")[:-1]
    secend =p.recvuntil("=")[:-1]
    result =p.recvline()
    if int(result) == int(first)+int(secend):
        p.sendline("BlackBird")
    else:
        p.sendline("WingS")
p.interactive()