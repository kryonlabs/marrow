#include <stdio.h>

int main(void) {
    printf("Test starting...\n");
    fflush(stdout);

    /* Just include the header, don't call anything */
    #include "../include/runtime/peb.h"

    printf("Header included, PEB size = %d\n", (int)sizeof(PEB));
    fflush(stdout);

    printf("Test complete!\n");
    return 0;
}
