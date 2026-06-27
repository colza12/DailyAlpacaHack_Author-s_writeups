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
