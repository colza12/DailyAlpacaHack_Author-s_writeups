# flag obfuscation : rev

IPv6 Obfuscationを用いて、flag出力コードを難読化したものをdeobfuscationする問題を作成しました。  
Windowsや難読化手法に触れるきっかけになってほしいという願いが込められています！  
stringsすると分割されたflagが出力されます。

## Challenge
flag_checkerが難読化されちゃった！

Attachment: flag-obfuscation.tar.gz

Difficulty: medium  
Topic : Obfuscation  

## writeup
難読化コードであるobfuscator.cと難読化されたデータであるdata.hが配布されます。  
obfuscator.cを読むと、flag_checker.exeのデータを16bytesずつに分割し、IPv6形式に変換していることが分かります。さらに変換後のデータがdata.hに保存されていることが分かります。

data.hがIPv6 Obfuscationを用いて難読化されたflag_checker.exeであることが分かるので、data.hをdeobfuscateして元の実行ファイルに復元します。  
復元コードは以下の通りです。本writeupではmingwを用いてcompileするようにできていますが、Pythonでコードを書いた方が簡易的です。
```solver.c
#define _WIN32_WINNT 0x0600

#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include "data.h"

int main() {
    FILE *f = fopen("checker.exe", "wb");
    if (!f) {
      printf("failed to create checker.exe\n");
      return 1;
    }

    for (int i = 0; i < ipv6_count; i++) {
        unsigned char buf[16];

        if (inet_pton(AF_INET6, ipv6_data[i], buf) != 1) {
            printf("ipv6 decode error\n");
            fclose(f);
            return 1;
        }

        fwrite(buf, 1, 16, f);
    }

    fclose(f);

    printf("checker.exe written successfully\n");
    return 0;
}
```
コンパイルコマンドは以下の通り。
```
$ x86_64-w64-mingw32-gcc solve.c -o solve.exe -lws2_32 -O2 -s
```
mingw64であれば、もう少し便利な関数(`RtlIpv6AddressToStringA`)が使えます。

solve.exeを実行してchecker.exeを作成します。  
このchecker.exeをデコンパイルすると、以下のようなコードが得られます。
```c flag_checker.c
#include <stdio.h>
#include <string.h>

int main() {
    char input[64];
    char flag[] = "Alpaca{ipv6_obfuscation_can_evade_signature}";

    printf("Input flag: ");
    fgets(input, sizeof(input), stdin);

    for (int i = 0; i < strlen(flag); i++) {
        if (input[i] != flag[i]) {
            printf("Wrong\n");
            return 0;
        }
    }

    printf("Correct!\n");
}
```

## flag

`Alpaca{ipv6_obfuscation_can_evade_signature}`
