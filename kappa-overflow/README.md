# kappa overflow : pwn

WindowsでのStack Buffer Overflowを体験する問題を作成しました。  
実はmingwを使用してコンパイルしているので、linuxで実行でき、標準のgdbであればデバッグできます！

## Challenge
かっぱが窓の外を覗いています！

`nc chal1.fwectf.com 8010`

Attachment: kappa-overflow.tar.gz

Difficulty: medium  
Topic : Windows  

## writeup
cache構造体のbufは64文字しか受け付けないが、そこにgets関数を用いて字数制限なしで標準入力を受け取るため、隣接するcache構造体のtargetまで上書きすることができます。  
その後、targetに指定されたアドレスに1を書き込むコードがあり、targetに指定されたアドレスがアクセスできない領域などの場合、Access Violationという例外が発生します。

よって、70文字前後の任意の文字列(aなど)を入力することで、targetに指定されたアドレスが不正なアドレスとなるため、Access Violationが発生し、flagが出力されます。

```
$ nc 34.170.146.252 57267
Input:
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

Exception code: 0xc0000005
Alpaca{7h3_n1gh7_sky_1s_634u71fu1}
```

## flag

`Alpaca{7h3_n1gh7_sky_1s_634u71fu1}`