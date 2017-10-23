#include <stdio.h>
#include <string.h>
char *SC =  "\x01\x60\x8f\xe2"
            "\x16\xff\x2f\xe1"
            "\x06\x22"
            "\x79\x46"
            "\x0e\x31"
            "\x01\x20"
            "\x04\x27"
            "\x01\xdf"
            "\x24\x1b"
            "\x20\x1c"
            "\x01\x27"
            "\x01\xdf"
            "\x6c\x73\x75\x73"
            "\x62\x0a\xc0\x46";

int main(void)
        {
                fprintf(stdout,"Longiud: %d\n",strlen(SC));
                (*(void(*)()) SC)();
        return 0;
        }
