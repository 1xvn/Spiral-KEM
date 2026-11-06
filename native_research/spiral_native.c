/* Experimental port of the fixed Spiral v0.3.1 OPT2 profile.
 * Secret arithmetic uses fixed bounds and addresses. Timing properties still
 * require compiler, CPU, OpenSSL provider and complete-caller validation.
 */
#include "spiral_native.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#define N 256u
#define Q 3329u
typedef uint16_t poly[N];
typedef poly vector[2];
typedef poly matrix[2][2];
typedef struct { uint8_t seed[32]; vector t; } public_key;
typedef struct { vector u; poly v; } ciphertext;
typedef struct { public_key pk; vector s; uint8_t fallback[32]; } secret_data;
struct sp_key { atomic_uint consumed; secret_data data; };

static const uint8_t DOMAIN[] = "Spiral-KEM-v0.3/research-only/";
static const uint8_t PARAMS[20] = {
    0,1,0,0, 2,0,0,0, 1,13,0,0, 1,0,0,0, 32,0,0,0
};
static const uint8_t PK_PREFIX[8] = {'S','K','W','1','P',6,0,0};
static const uint8_t CT_PREFIX[8] = {'S','K','W','1','C',6,0,0};

static void erase(void *p, size_t n) { OPENSSL_cleanse(p, n); }

/* x < 2*Q. Unsigned wraparound is intentional and defined by C. */
static uint16_t reduce_small(uint32_t x) {
    uint32_t y = x - Q;
    return (uint16_t)(y + ((y >> 31) * Q));
}

/* Reciprocal reduction, valid over all uint32_t. Remainder is < 2*Q. */
static uint16_t reduce_word(uint32_t x) {
    uint32_t quotient = (uint32_t)(((uint64_t)x * 1290167u) >> 32);
    return reduce_small(x - quotient * Q);
}

static void add(poly out, const poly a, const poly b) {
    for (size_t i = 0; i < N; ++i) out[i] = reduce_small((uint32_t)a[i] + b[i]);
}

static void sub(poly out, const poly a, const poly b) {
    for (size_t i = 0; i < N; ++i) out[i] = reduce_small((uint32_t)a[i] + Q - b[i]);
}

static void multiply(poly out, const poly a, const poly b) {
    /* Every accumulator is <= N*Q^2 < 2^32. Loop bounds and indices are public. */
    for (size_t i = 0; i < N; ++i) {
        uint32_t total = 0;
        for (size_t j = 0; j <= i; ++j) total += (uint32_t)a[j] * b[i-j];
        for (size_t j = i+1; j < N; ++j) total += Q*Q - (uint32_t)a[j] * b[i+N-j];
        out[i] = reduce_word(total);
    }
}

static void dot(poly out, const vector a, const vector b) {
    poly temporary;
    memset(out, 0, sizeof(poly));
    for (size_t i = 0; i < 2; ++i) {
        multiply(temporary, a[i], b[i]);
        add(out, out, temporary);
    }
    erase(temporary, sizeof temporary);
}

static int xof(const uint8_t *label, size_t label_len, const uint8_t *payload,
               size_t payload_len, uint8_t *out, size_t length) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    uint8_t size[2] = {(uint8_t)label_len, (uint8_t)(label_len >> 8)};
    if (ctx == NULL) return SP_CRYPTO;
    int ok = EVP_DigestInit_ex(ctx, EVP_shake256(), NULL)
        && EVP_DigestUpdate(ctx, DOMAIN, sizeof DOMAIN - 1)
        && EVP_DigestUpdate(ctx, PARAMS, sizeof PARAMS)
        && EVP_DigestUpdate(ctx, size, sizeof size)
        && EVP_DigestUpdate(ctx, label, label_len)
        && EVP_DigestUpdate(ctx, payload, payload_len)
        && EVP_DigestFinalXOF(ctx, out, length);
    EVP_MD_CTX_free(ctx);
    if (!ok) erase(out, length);
    return ok ? SP_OK : SP_CRYPTO;
}

static int sha3(const uint8_t *data, size_t length, uint8_t out[32]) {
    unsigned int actual = 0;
    if (!EVP_Digest(data, length, out, &actual, EVP_sha3_256(), NULL) || actual != 32) {
        erase(out, 32);
        return SP_CRYPTO;
    }
    return SP_OK;
}

static void pack12(uint8_t *out, const poly a) {
    for (size_t i = 0; i < N; i += 2) {
        out[3*i/2] = (uint8_t)a[i];
        out[3*i/2+1] = (uint8_t)((a[i] >> 8) | (a[i+1] << 4));
        out[3*i/2+2] = (uint8_t)(a[i+1] >> 4);
    }
}

static int unpack12(poly out, const uint8_t *data) {
    uint32_t invalid = 0;
    for (size_t i = 0; i < N; i += 2) {
        out[i] = (uint16_t)(data[3*i/2] | ((data[3*i/2+1] & 15u) << 8));
        out[i+1] = (uint16_t)((data[3*i/2+1] >> 4) | (data[3*i/2+2] << 4));
        invalid |= (uint32_t)(out[i] >= Q) | (uint32_t)(out[i+1] >= Q);
    }
    return invalid ? SP_INPUT : SP_OK; /* External, public parsing decision. */
}

static void pack16(uint8_t *out, const poly a) {
    for (size_t i = 0; i < N; ++i) {
        out[2*i] = (uint8_t)a[i];
        out[2*i+1] = (uint8_t)(a[i] >> 8);
    }
}

static int parse_pk(public_key *pk, const uint8_t *wire, size_t length) {
    if (wire == NULL || length != SP_PK_BYTES || memcmp(wire, PK_PREFIX, 8)) return SP_INPUT;
    memcpy(pk->seed, wire+8, 32);
    int a = unpack12(pk->t[0], wire+40);
    int b = unpack12(pk->t[1], wire+424);
    return a | b;
}

static int parse_ct(ciphertext *ct, const uint8_t *wire, size_t length) {
    if (wire == NULL || length != SP_CT_BYTES || memcmp(wire, CT_PREFIX, 8)) return SP_INPUT;
    int a = unpack12(ct->u[0], wire+8);
    int b = unpack12(ct->u[1], wire+392);
    int c = unpack12(ct->v, wire+776);
    return a | b | c;
}

static void public_wire(uint8_t wire[SP_PK_BYTES], const public_key *pk) {
    memcpy(wire, PK_PREFIX, 8);
    memcpy(wire+8, pk->seed, 32);
    pack12(wire+40, pk->t[0]);
    pack12(wire+424, pk->t[1]);
}

static void cipher_wire(uint8_t wire[SP_CT_BYTES], const ciphertext *ct) {
    memcpy(wire, CT_PREFIX, 8);
    pack12(wire+8, ct->u[0]); pack12(wire+392, ct->u[1]); pack12(wire+776, ct->v);
}

static int public_hash(uint8_t hash[32], const public_key *pk) {
    uint8_t wire[1109];
    size_t prefix = sizeof DOMAIN - 1;
    memcpy(wire, DOMAIN, prefix);
    memcpy(wire+prefix, "pk/", 3);
    memcpy(wire+prefix+3, PARAMS, 20);
    memcpy(wire+53, pk->seed, 32);
    pack16(wire+85, pk->t[0]); pack16(wire+597, pk->t[1]);
    return sha3(wire, sizeof wire, hash);
}

static int cipher_hash(uint8_t hash[32], const ciphertext *ct) {
    uint8_t wire[1589];
    size_t prefix = sizeof DOMAIN - 1;
    memcpy(wire, DOMAIN, prefix);
    memcpy(wire+prefix, "ct/", 3);
    memcpy(wire+prefix+3, PARAMS, 20);
    pack16(wire+53, ct->u[0]); pack16(wire+565, ct->u[1]); pack16(wire+1077, ct->v);
    return sha3(wire, sizeof wire, hash);
}

static int small_poly(poly out, const uint8_t seed[32], const uint8_t *label, size_t length) {
    uint8_t framed[64], stream[512];
    memcpy(framed, "small/", 6); memcpy(framed+6, label, length);
    int status = xof(framed, length+6, seed, 32, stream, sizeof stream);
    if (status == SP_OK) {
        for (size_t i = 0; i < N; ++i) {
            uint32_t value = (stream[2*i] & 1u) + Q - (stream[2*i+1] & 1u);
            out[i] = reduce_small(value);
        }
    }
    erase(stream, sizeof stream);
    return status;
}

static int small_vector(vector out, const uint8_t seed[32], const char *label, size_t length) {
    uint8_t framed[32];
    memcpy(framed, label, length);
    framed[length] = '/'; framed[length+2] = 0;
    for (size_t i = 0; i < 2; ++i) {
        framed[length+1] = (uint8_t)i;
        int status = small_poly(out[i], seed, framed, length+3);
        if (status) return status;
    }
    return SP_OK;
}

static int base_matrix(matrix out, const uint8_t seed[32]) {
    /* Rejection sampling depends exclusively on the public matrix seed. */
    uint8_t label[19], input[36], stream[256];
    memcpy(label, "uniform/matrix/", 15);
    memcpy(input, seed, 32);
    for (size_t row = 0; row < 2; ++row) {
        for (size_t column = 0; column < 2; ++column) {
            label[15] = (uint8_t)row; label[16] = 0;
            label[17] = (uint8_t)column; label[18] = 0;
            size_t accepted = 0;
            uint32_t counter = 0;
            while (accepted < N) {
                for (size_t k = 0; k < 4; ++k) input[32+k] = (uint8_t)(counter >> (8*k));
                if (xof(label, sizeof label, input, sizeof input, stream, sizeof stream)) return SP_CRYPTO;
                for (size_t k = 0; k < sizeof stream && accepted < N; k += 2) {
                    uint32_t candidate = stream[k] | ((uint32_t)stream[k+1] << 8);
                    if (candidate < 63251u) out[row][column][accepted++] = reduce_word(candidate);
                }
                if (++counter == 0) return SP_CRYPTO;
            }
        }
    }
    return SP_OK;
}

static void encode(poly out, const uint8_t message[32]) {
    for (size_t i = 0; i < N; ++i) out[i] = (uint16_t)(((message[i/8] >> (i%8)) & 1u) * 1664u);
}

static void decode(uint8_t message[32], const poly a) {
    memset(message, 0, 32);
    for (size_t i = 0; i < N; ++i) {
        uint32_t above = (832u - a[i]) >> 31;
        uint32_t below = 1u ^ ((2496u - a[i]) >> 31);
        message[i/8] |= (uint8_t)((above & below) << (i%8));
    }
}

static int encrypt_message(ciphertext *ct, const public_key *pk, const uint8_t message[32]) {
    uint8_t coins[32], coin_input[64];
    vector r, e1;
    poly e2, temporary, encoded;
    matrix a;
    int status = public_hash(coin_input+32, pk);
    memcpy(coin_input, message, 32);
    if (status == SP_OK) status = xof((const uint8_t *)"coins/", 6, coin_input, 64, coins, 32);
    if (status == SP_OK) status = small_vector(r, coins, "enc/r", 5);
    if (status == SP_OK) status = small_vector(e1, coins, "enc/e1", 6);
    if (status == SP_OK) status = small_poly(e2, coins, (const uint8_t *)"enc/e2", 6);
    if (status == SP_OK) status = base_matrix(a, pk->seed);
    if (status == SP_OK) {
        for (size_t column = 0; column < 2; ++column) {
            memset(ct->u[column], 0, sizeof(poly));
            for (size_t row = 0; row < 2; ++row) {
                multiply(temporary, a[row][column], r[row]);
                add(ct->u[column], ct->u[column], temporary);
            }
            add(ct->u[column], ct->u[column], e1[column]);
        }
        dot(ct->v, pk->t, r);
        add(ct->v, ct->v, e2);
        encode(encoded, message); add(ct->v, ct->v, encoded);
    }
    erase(coins, sizeof coins); erase(coin_input, sizeof coin_input);
    erase(r, sizeof r); erase(e1, sizeof e1); erase(e2, sizeof e2);
    erase(temporary, sizeof temporary); erase(encoded, sizeof encoded);
    return status;
}

static int shared(uint8_t out[32], const public_key *pk, const uint8_t message[32], const ciphertext *ct) {
    uint8_t data[96];
    memcpy(data, message, 32);
    int status = public_hash(data+32, pk);
    if (status == SP_OK) status = cipher_hash(data+64, ct);
    if (status == SP_OK) status = xof((const uint8_t *)"shared-key/", 11, data, sizeof data, out, 32);
    erase(data, sizeof data);
    return status;
}

static int keygen_seeded(const uint8_t seeds[96], uint8_t wire[SP_PK_BYTES], sp_key **result) {
    matrix a;
    vector e;
    poly temporary;
    *result = NULL;
    sp_key *key = OPENSSL_zalloc(sizeof *key);
    if (key == NULL) return SP_CRYPTO;
    atomic_init(&key->consumed, 0);
    memcpy(key->data.pk.seed, seeds, 32);
    memcpy(key->data.fallback, seeds+64, 32);
    int status = base_matrix(a, seeds);
    if (status == SP_OK) status = small_vector(key->data.s, seeds+32, "key/s", 5);
    if (status == SP_OK) status = small_vector(e, seeds+32, "key/e", 5);
    if (status == SP_OK) {
        for (size_t row = 0; row < 2; ++row) {
            dot(temporary, a[row], key->data.s);
            add(key->data.pk.t[row], temporary, e[row]);
        }
        public_wire(wire, &key->data.pk);
        *result = key;
    } else {
        OPENSSL_clear_free(key, sizeof *key);
    }
    erase(e, sizeof e); erase(temporary, sizeof temporary);
    return status;
}

int sp_keygen(uint8_t pk[SP_PK_BYTES], sp_key **key) {
    uint8_t seeds[96];
    if (key == NULL || pk == NULL) return SP_INPUT;
    *key = NULL; memset(pk, 0, SP_PK_BYTES);
    int status = RAND_priv_bytes(seeds, sizeof seeds) == 1 ? SP_OK : SP_CRYPTO;
    if (status == SP_OK) status = keygen_seeded(seeds, pk, key);
    erase(seeds, sizeof seeds);
    return status;
}

static int encaps_message(const public_key *pk, const uint8_t message[32], uint8_t wire[SP_CT_BYTES], uint8_t ss[32]) {
    ciphertext ct;
    int status = encrypt_message(&ct, pk, message);
    if (status == SP_OK) status = shared(ss, pk, message, &ct);
    if (status == SP_OK) cipher_wire(wire, &ct);
    erase(&ct, sizeof ct);
    return status;
}

int sp_encaps(const uint8_t *pk_wire, size_t pk_len, uint8_t ct[SP_CT_BYTES], uint8_t ss[SP_SS_BYTES]) {
    public_key pk;
    uint8_t message[32];
    if (ct == NULL || ss == NULL) return SP_INPUT;
    memset(ct, 0, SP_CT_BYTES); memset(ss, 0, SP_SS_BYTES);
    int status = parse_pk(&pk, pk_wire, pk_len);
    if (status == SP_OK && RAND_priv_bytes(message, sizeof message) != 1) status = SP_CRYPTO;
    if (status == SP_OK) status = encaps_message(&pk, message, ct, ss);
    erase(message, sizeof message);
    if (status) { erase(ct, SP_CT_BYTES); erase(ss, SP_SS_BYTES); }
    return status;
}

int sp_decaps_once(sp_key *key, const uint8_t *wire, size_t length, uint8_t out[SP_SS_BYTES]) {
    if (out == NULL || key == NULL) return SP_INPUT;
    memset(out, 0, SP_SS_BYTES);
    unsigned int expected_state = 0;
    if (!atomic_compare_exchange_strong(&key->consumed, &expected_state, 1)) return SP_USED;
    ciphertext ct, expected;
    poly aligned, product;
    uint8_t message[32], expected_wire[SP_CT_BYTES], good[32], fallback[32], data[96];
    int status = parse_ct(&ct, wire, length);
    if (status == SP_OK) {
        dot(product, key->data.s, ct.u);
        sub(aligned, ct.v, product);
        decode(message, aligned);
        status = encrypt_message(&expected, &key->data.pk, message);
    }
    if (status == SP_OK) status = shared(good, &key->data.pk, message, &ct);
    if (status == SP_OK) {
        memcpy(data, key->data.fallback, 32);
        status = public_hash(data+32, &key->data.pk);
    }
    if (status == SP_OK) status = cipher_hash(data+64, &ct);
    if (status == SP_OK) status = xof((const uint8_t *)"fallback/", 9, data, sizeof data, fallback, 32);
    if (status == SP_OK) {
        cipher_wire(expected_wire, &expected);
        uint32_t mask = 0u - (uint32_t)(CRYPTO_memcmp(wire, expected_wire, SP_CT_BYTES) == 0);
        for (size_t i = 0; i < 32; ++i) out[i] = (uint8_t)((good[i] & mask) | (fallback[i] & ~mask));
    }
    erase(&ct, sizeof ct); erase(&expected, sizeof expected);
    erase(aligned, sizeof aligned); erase(product, sizeof product); erase(message, sizeof message);
    erase(expected_wire, sizeof expected_wire); erase(good, sizeof good);
    erase(fallback, sizeof fallback); erase(data, sizeof data);
    erase(&key->data, sizeof key->data);
    atomic_store(&key->consumed, 2);
    if (status) erase(out, SP_SS_BYTES);
    return status;
}

void sp_key_destroy(sp_key **key) {
    if (key != NULL && *key != NULL) {
        OPENSSL_clear_free(*key, sizeof **key);
        *key = NULL;
    }
}

#ifdef SPIRAL_TESTING
int sp_test_keygen(const uint8_t seeds[96], uint8_t pk[SP_PK_BYTES], sp_key **key) {
    if (seeds == NULL || pk == NULL || key == NULL) return SP_INPUT;
    memset(pk, 0, SP_PK_BYTES);
    return keygen_seeded(seeds, pk, key);
}

int sp_test_encaps(const uint8_t *wire, size_t length, const uint8_t message[32], uint8_t ct[SP_CT_BYTES], uint8_t ss[32]) {
    public_key pk;
    if (message == NULL || ct == NULL || ss == NULL) return SP_INPUT;
    memset(ct, 0, SP_CT_BYTES); memset(ss, 0, 32);
    int status = parse_pk(&pk, wire, length);
    if (status == SP_OK) status = encaps_message(&pk, message, ct, ss);
    if (status) { erase(ct, SP_CT_BYTES); erase(ss, 32); }
    return status;
}

int sp_test_cleared(const sp_key *key) {
    if (key == NULL || atomic_load(&key->consumed) != 2) return 0;
    const uint8_t *data = (const uint8_t *)&key->data;
    unsigned int remaining = 0;
    for (size_t i = 0; i < sizeof key->data; ++i) remaining |= data[i];
    return remaining == 0;
}

void sp_test_poly_mul(uint16_t out[256], const uint16_t a[256], const uint16_t b[256]) {
    multiply(out, a, b);
}
#endif
