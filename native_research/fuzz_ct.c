/* Deterministic public-input correctness/memory target, not a security proof.
 * Compile this oracle without coverage and spiral_native.c with coverage. */
#ifndef SPIRAL_TESTING
#define SPIRAL_TESTING
#endif
#include "spiral_native.h"
#include <fuzz_ct_vectors.h>
#include <assert.h>
#include <openssl/crypto.h>
#include <stdint.h>
#include <string.h>

#ifdef NDEBUG
#error "Fuzz correctness checks require assertions"
#endif

_Static_assert(SP_PK_BYTES == 808 && SP_CT_BYTES == 1160 && SP_SS_BYTES == 32,
               "Review the independent format oracle if the profile changes");
_Static_assert(sizeof FIXTURE_SEEDS == 96 && sizeof FIXTURE_PK == 808 &&
               sizeof FIXTURE_CT == 1160 && sizeof FIXTURE_SS == 32,
               "The public deterministic fixture has unexpected dimensions");

enum { FUZZ_CT_MAX_BYTES = 1280 };

/* Independent format oracle: fixed header followed by a generic little-endian
 * 12-bit stream. Do not call runtime parse/unpack helpers here. */
static int canonical(const uint8_t *data, size_t size) {
    static const uint8_t prefix[8] = {'S', 'K', 'W', '1', 'C', 6, 0, 0};
    if (size != 1160 || data == NULL || memcmp(data, prefix, sizeof prefix) != 0)
        return 0;

    size_t at = sizeof prefix;
    uint32_t bits = 0;
    unsigned int available = 0;
    for (size_t i = 0; i < 768; ++i) {
        while (available < 12) {
            bits |= (uint32_t)data[at++] << available;
            available += 8;
        }
        if ((bits & 4095u) >= 3329) return 0;
        bits >>= 12;
        available -= 12;
    }
    return at == size && available == 0;
}

static int all_zero(const uint8_t *data, size_t size) {
    unsigned int remaining = 0;
    for (size_t i = 0; i < size; ++i) remaining |= data[i];
    return remaining == 0;
}

struct case_result {
    int status;
    int canonical;
    uint8_t shared_secret[SP_SS_BYTES];
};

static void check_input(const uint8_t *data, size_t size,
                        struct case_result *result) {
    /* All key material comes from the public fixture. Each attempt owns a fresh
     * key; the ciphertext, public key, and both output buffers stay disjoint. */
    sp_key *key = NULL;
    uint8_t original[FUZZ_CT_MAX_BYTES];
    uint8_t pk[SP_PK_BYTES], ss[SP_SS_BYTES], used_ss[SP_SS_BYTES];
    assert(size <= sizeof original);
    if (size != 0) {
        assert(data != NULL);
        memcpy(original, data, size);
    }
    memset(pk, 0xa5, sizeof pk);
    memset(ss, 0xa5, sizeof ss);
    memset(used_ss, 0xa5, sizeof used_ss);
    int expected = canonical(data, size);
    int golden = size == sizeof FIXTURE_CT && data != NULL &&
                 memcmp(data, FIXTURE_CT, sizeof FIXTURE_CT) == 0;

    assert(sp_test_keygen(FIXTURE_SEEDS, pk, &key) == SP_OK);
    assert(key != NULL);
    assert(memcmp(pk, FIXTURE_PK, sizeof pk) == 0);

    int status = sp_decaps_once(key, data, size, ss);
    if (size != 0) assert(memcmp(data, original, size) == 0);
    assert(status == (expected ? SP_OK : SP_INPUT));
    if (!expected) assert(all_zero(ss, sizeof ss));
    if (golden) assert(memcmp(ss, FIXTURE_SS, sizeof ss) == 0);
    assert(sp_test_cleared(key));

    assert(sp_decaps_once(key, data, size, used_ss) == SP_USED);
    if (size != 0) assert(memcmp(data, original, size) == 0);
    assert(all_zero(used_ss, sizeof used_ss));
    assert(sp_test_cleared(key));
    sp_key_destroy(&key);
    assert(key == NULL);
    sp_key_destroy(&key);
    assert(key == NULL);

    if (result != NULL) {
        result->status = status;
        result->canonical = expected;
        memcpy(result->shared_secret, ss, sizeof ss);
    }
    OPENSSL_cleanse(ss, sizeof ss);
    OPENSSL_cleanse(used_ss, sizeof used_ss);
    OPENSSL_cleanse(pk, sizeof pk);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    check_input(data, size, NULL);
    return 0;
}

#ifdef FUZZ_CT_REPLAY_MAIN
#include <errno.h>
#include <openssl/sha.h>
#include <stdio.h>

static void hex_encode(const uint8_t *data, size_t size, char *out) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < size; ++i) {
        out[2 * i] = digits[data[i] >> 4];
        out[2 * i + 1] = digits[data[i] & 15u];
    }
    out[2 * size] = '\0';
}

static int replay_file(const char *path) {
    uint8_t data[FUZZ_CT_MAX_BYTES], digest[SHA256_DIGEST_LENGTH];
    FILE *input = fopen(path, "rb");
    if (input == NULL) {
        fprintf(stderr, "Cannot open replay input %s: %s\n", path, strerror(errno));
        return 1;
    }
    size_t size = fread(data, 1, sizeof data, input);
    if (ferror(input)) {
        fprintf(stderr, "Replay input read failed or was truncated: %s\n", path);
        (void)fclose(input);
        return 1;
    }
    /* Detect excess bytes explicitly instead of replaying a truncated prefix. */
    int extra = fgetc(input);
    if (ferror(input)) {
        fprintf(stderr, "Replay input read failed or was truncated: %s\n", path);
        (void)fclose(input);
        return 1;
    }
    if (extra != EOF) {
        fprintf(stderr, "Replay input exceeds the %u-byte limit: %s\n",
                (unsigned int)FUZZ_CT_MAX_BYTES, path);
        (void)fclose(input);
        return 1;
    }
    if (fclose(input) != 0) {
        fprintf(stderr, "Cannot close replay input %s: %s\n", path, strerror(errno));
        return 1;
    }

    struct case_result result;
    char digest_hex[2 * SHA256_DIGEST_LENGTH + 1];
    char shared_secret_hex[2 * SP_SS_BYTES + 1];
    check_input(data, size, &result);
    assert(SHA256(data, size, digest) != NULL);
    hex_encode(digest, sizeof digest, digest_hex);
    hex_encode(result.shared_secret, sizeof result.shared_secret, shared_secret_hex);
    /* These are outputs of a public fixed-seed fixture, never production keys. */
    int written = printf("{\"sha256\":\"%s\",\"status\":%d,"
                         "\"shared_secret_hex\":\"%s\",\"canonical\":%s}\n",
                         digest_hex, result.status, shared_secret_hex,
                         result.canonical ? "true" : "false");
    OPENSSL_cleanse(&result, sizeof result);
    OPENSSL_cleanse(shared_secret_hex, sizeof shared_secret_hex);
    return written < 0 ? 1 : 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s INPUT [INPUT ...]\n", argv[0]);
        return 2;
    }
    for (int i = 1; i < argc; ++i)
        if (replay_file(argv[i]) != 0) return 1;
    if (fflush(stdout) != 0) {
        fprintf(stderr, "Cannot write replay output: %s\n", strerror(errno));
        return 1;
    }
    return 0;
}
#endif
