/* Native-only sanitizer corpus and explicit crypto/RNG failure injection. */
#define SPIRAL_TESTING
#include "spiral_native.c"
#include <assert.h>
#include <stdio.h>

static int rng_failure = 0;
static unsigned int rng_calls = 0;
static int digest_failure = 0;
EVP_MD_CTX *__real_EVP_MD_CTX_new(void);
EVP_MD_CTX *__wrap_EVP_MD_CTX_new(void) {
    if (digest_failure) return NULL;
    return __real_EVP_MD_CTX_new();
}
int __real_RAND_priv_bytes(unsigned char *, int);
int __wrap_RAND_priv_bytes(unsigned char *out, int size) {
    ++rng_calls;
    if (rng_failure) { memset(out, 0xa5, (size_t)size); return 0; }
    return __real_RAND_priv_bytes(out, size);
}

static int all_zero(const void *data, size_t size) {
    const uint8_t *p = data;
    unsigned int value = 0;
    for (size_t i = 0; i < size; ++i) value |= p[i];
    return value == 0;
}

int main(void) {
    uint8_t seeds[96], pk[SP_PK_BYTES], ct[SP_CT_BYTES], ss[32], recovered[32], message[32];
    for (size_t i = 0; i < sizeof seeds; ++i) seeds[i] = (uint8_t)i;
    memset(message, 0x95, sizeof message);
    sp_key *key = NULL;
    assert(sp_test_keygen(seeds, pk, &key) == SP_OK);
    assert(sp_test_encaps(pk, sizeof pk, message, ct, ss) == SP_OK);
    assert(sp_decaps_once(key, ct, sizeof ct, recovered) == SP_OK);
    assert(CRYPTO_memcmp(ss, recovered, 32) == 0);
    assert(sp_test_cleared(key));
    sp_key_destroy(&key);
    sp_key_destroy(&key);

    rng_failure = 1;
    memset(pk, 0xff, sizeof pk);
    assert(sp_keygen(pk, &key) == SP_CRYPTO);
    assert(key == NULL && all_zero(pk, sizeof pk));
    assert(sp_test_keygen(seeds, pk, &key) == SP_OK);
    memset(ct, 0xff, sizeof ct); memset(ss, 0xff, sizeof ss);
    assert(sp_encaps(pk, sizeof pk, ct, ss) == SP_CRYPTO);
    assert(all_zero(ct, sizeof ct) && all_zero(ss, sizeof ss));
    unsigned int before = rng_calls;
    assert(sp_encaps(pk, sizeof pk-1, ct, ss) == SP_INPUT);
    assert(rng_calls == before);
    assert(sp_decaps_once(key, NULL, 1160, recovered) == SP_INPUT);
    assert(sp_test_cleared(key) && all_zero(recovered, sizeof recovered));
    sp_key_destroy(&key);
    rng_failure = 0;

    assert(sp_test_keygen(seeds, pk, &key) == SP_OK);
    assert(sp_test_encaps(pk, sizeof pk, message, ct, ss) == SP_OK);
    digest_failure = 1;
    assert(sp_decaps_once(key, ct, sizeof ct, recovered) == SP_CRYPTO);
    assert(sp_test_cleared(key) && all_zero(recovered, sizeof recovered));
    sp_key_destroy(&key);
    assert(sp_keygen(pk, &key) == SP_CRYPTO);
    assert(key == NULL && all_zero(pk, sizeof pk));
    digest_failure = 0;

    /* Public-input mutation corpus; lengths deliberately include huge values. */
    uint8_t input[2048];
    uint32_t rng = 0x12345678u;
    for (unsigned int sample = 0; sample < 20000; ++sample) {
        for (size_t i = 0; i < sizeof input; ++i) {
            rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5;
            input[i] = (uint8_t)rng;
        }
        size_t length = sample % (sizeof input+1);
        if (sample % 7 == 0) length = (size_t)-1;
        if (sample % 11 == 0) memcpy(input, PK_PREFIX, 8);
        public_key parsed_pk;
        ciphertext parsed_ct;
        (void)parse_pk(&parsed_pk, input, length);
        if (sample % 11 == 0) memcpy(input, CT_PREFIX, 8);
        (void)parse_ct(&parsed_ct, input, length);
    }
    assert(parse_pk(NULL, NULL, 808) == SP_INPUT);
    assert(parse_ct(NULL, NULL, 1160) == SP_INPUT);
    puts("native failure injection and 20000 public-input corpus cases passed");
    return 0;
}
