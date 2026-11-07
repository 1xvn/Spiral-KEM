/* Deterministic public-input correctness/memory target, not a security proof.
 * The oracle is compiled without coverage; spiral_native.c gets coverage. */
#define SPIRAL_TESTING
#include "spiral_native.h"
#include <assert.h>
#include <openssl/crypto.h>
#include <stdint.h>
#include <string.h>

#ifdef NDEBUG
#error "Fuzz correctness checks require assertions"
#endif
_Static_assert(SP_PK_BYTES == 808 && SP_CT_BYTES == 1160 && SP_SS_BYTES == 32,
               "Review the independent format oracle if the profile changes");

/* Spec oracle: fixed header and generic little-endian 12-bit stream.
 * This deliberately does not call the runtime's parse/unpack functions. */
static int canonical(const uint8_t *data, size_t size, int public_key) {
    const uint8_t prefix[8] = {'S','K','W','1',public_key ? 'P' : 'C',6,0,0};
    const size_t expected_size = public_key ? 808 : 1160;
    size_t at = public_key ? 40 : 8;
    if (size != expected_size || memcmp(data, prefix, 8) != 0) return 0;
    uint32_t bits = 0;
    unsigned int available = 0;
    const size_t coefficients = public_key ? 512 : 768;
    for (size_t i = 0; i < coefficients; ++i) {
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

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static const uint8_t message[32] = {0x95}; /* Public fixed test message. */
    uint8_t ct[SP_CT_BYTES], ss[SP_SS_BYTES];
    memset(ct, 0xa5, sizeof ct);
    memset(ss, 0xa5, sizeof ss);
    int expected = canonical(data, size, 1);
    int status = sp_test_encaps(data, size, message, ct, ss);
    assert(status == (expected ? SP_OK : SP_INPUT));
    if (status == SP_INPUT) {
        for (size_t i = 0; i < sizeof ct; ++i) assert(ct[i] == 0);
        for (size_t i = 0; i < sizeof ss; ++i) assert(ss[i] == 0);
    } else {
        assert(canonical(ct, sizeof ct, 0));
    }
    OPENSSL_cleanse(ss, sizeof ss);
    OPENSSL_cleanse(ct, sizeof ct);
    return 0;
}
