/* Dynamic secret-taint assessment using ordinary Valgrind Memcheck requests. */
#define SPIRAL_TESTING
#include "spiral_native.c"
#include <assert.h>
#include <stdio.h>
#include <valgrind/memcheck.h>

int main(int argc, char **argv) {
    uint8_t seeds[96], wire[SP_PK_BYTES], ct[SP_CT_BYTES], ss[32], message[32];
    for (size_t i=0;i<96;++i) seeds[i]=(uint8_t)i;
    memset(message,0xc1,sizeof message);
    sp_key *key=NULL;
    assert(sp_test_keygen(seeds,wire,&key)==SP_OK);
    /* Warm the provider on fully initialized test inputs before tainting. */
    assert(sp_test_encaps(wire,sizeof wire,message,ct,ss)==SP_OK);
    sp_key_destroy(&key);
    if (argc==2 && strcmp(argv[1],"positive")==0) {
        volatile unsigned int secret=1;
        VALGRIND_MAKE_MEM_UNDEFINED((void *)&secret,sizeof secret);
        if (secret) puts("intentional positive-control branch");
        VALGRIND_MAKE_MEM_DEFINED((void *)&secret,sizeof secret);
        return 0;
    }
    for (unsigned int trial=0;trial<4;++trial) {
        VALGRIND_MAKE_MEM_UNDEFINED(seeds+32,64);
        int status=sp_test_keygen(seeds,wire,&key);
        VALGRIND_MAKE_MEM_DEFINED(seeds+32,64);
        /* The public key is an intentional public output of key generation. */
        VALGRIND_MAKE_MEM_DEFINED(wire,sizeof wire);
        assert(status==SP_OK && key!=NULL);
        VALGRIND_MAKE_MEM_DEFINED(&key->data.pk,sizeof key->data.pk);
        VALGRIND_MAKE_MEM_UNDEFINED(message,sizeof message);
        status=sp_test_encaps(wire,sizeof wire,message,ct,ss);
        VALGRIND_MAKE_MEM_DEFINED(message,sizeof message);
        VALGRIND_MAKE_MEM_DEFINED(ct,sizeof ct);
        VALGRIND_MAKE_MEM_DEFINED(ss,sizeof ss);
        assert(status==SP_OK);
        if (trial%2) ct[8]^=1;
        VALGRIND_MAKE_MEM_UNDEFINED(key->data.s,sizeof key->data.s);
        VALGRIND_MAKE_MEM_UNDEFINED(key->data.fallback,sizeof key->data.fallback);
        status=sp_decaps_once(key,ct,sizeof ct,ss);
        VALGRIND_MAKE_MEM_DEFINED(ss,sizeof ss);
        assert(status==SP_OK);
        assert(sp_test_cleared(key));
        sp_key_destroy(&key);
    }
    puts("secret-taint native test completed");
    return 0;
}
