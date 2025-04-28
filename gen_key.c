// gen_key.c
#include "dh.h"
#include "keys.h"
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <base_filename>\n", argv[0]);
        return 1;
    }
    const char *fname = argv[1];
    dhKey k;
    initKey(&k);
    // generate a fresh keypair
    dhGen(k.SK, k.PK);
    // write both private and public
    if (writeDH(fname, &k) != 0) {
        fprintf(stderr, "Error writing key %s\n", fname);
        return 1;
    }
    printf("Wrote %s (private) and %s.pub (public)\n", fname, fname);
    shredKey(&k);
    return 0;
}
