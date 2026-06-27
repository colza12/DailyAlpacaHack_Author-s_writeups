# voyage : misc

cpioファイルを展開するだけの問題を作成しました。  
cpioに触れてkernel exploitへの導入ハードルを下げたいという願いを込めました。  
stringsで頑張ってもflagを取得できます。

## Challenge
cpio voyage  
flagは`/flag.txt`にあります。`print_flag.py`にflagのpathを設定して実行するとflagを取得できます。

Attachment: voyage.tar.gz

Difficulty: easy  
Topic : Archive  

## writeup
bzImage、initramfs.cpio、run.sh、print_flag.pyが配布されます。  
run.shを実行するとuser権限でLinuxのshellを起動できます。ここはおまけで簡易的に作成した部分になります。弄って遊んでみてください。  
ただし、配布されたままの状態ではflagを取得できないので、cpioファイルを展開します。

展開するときのコマンドは以下の通りです。root権限で操作することをおすすめします。
```
# mkdir root
# cd root && cpio -idv < ../../distfiles/initramfs.cpio
```
これでflag.txtにアクセスできるようになります。  
print_flag.pyにflagのpathである`root/flag.txt`を入力して実行するとflagを取得できます。
```
$ python3 print_flag.py
ヽ(・ω・oヽ)かっぱぱヽ(o・ω・o)ﾉかっぱ(ﾉo・ω・)ﾉぱぱー♪
flag is here: Alpaca{Let's_get_started_with_kernel_exploits!!!!!}
```
stringsでは得られない養分があります。

## flag

`Alpaca{Let's_get_started_with_kernel_exploits!!!!!}`
