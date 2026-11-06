#ifndef SPIRAL_NATIVE_H
#define SPIRAL_NATIVE_H
#include <stddef.h>
#include <stdint.h>

#if defined(__GNUC__)
#define SP_API __attribute__((visibility("default")))
#else
#define SP_API
#endif

/* Research-only, fixed n=256 profile. Caller owns all public buffers.
 * A key may be decapsulated once, including a malformed-input attempt.
 * Join every caller before destroying a key. No concurrent destroy is allowed.
 * Supply live, correctly sized, non-overlapping buffers and an initially NULL
 * key output. NULL output pointers are caller errors, not decapsulation attempts.
 * Do not copy the opaque key or use a pointer after sp_key_destroy.
 */
typedef struct sp_key sp_key;
enum { SP_OK = 0, SP_INPUT = 1, SP_CRYPTO = 2, SP_USED = 3 };
enum { SP_PK_BYTES = 808, SP_CT_BYTES = 1160, SP_SS_BYTES = 32 };

SP_API int sp_keygen(uint8_t pk[SP_PK_BYTES], sp_key **key);
SP_API int sp_encaps(const uint8_t *pk, size_t pk_len,
                     uint8_t ct[SP_CT_BYTES], uint8_t ss[SP_SS_BYTES]);
SP_API int sp_decaps_once(sp_key *key, const uint8_t *ct, size_t ct_len,
                         uint8_t ss[SP_SS_BYTES]);
SP_API void sp_key_destroy(sp_key **key);

#ifdef SPIRAL_TESTING
/* Exported exclusively by the separate testing build. All test seeds are public. */
SP_API int sp_test_keygen(const uint8_t seeds[96], uint8_t pk[SP_PK_BYTES], sp_key **key);
SP_API int sp_test_encaps(const uint8_t *pk, size_t pk_len, const uint8_t message[32],
                          uint8_t ct[SP_CT_BYTES], uint8_t ss[SP_SS_BYTES]);
SP_API int sp_test_cleared(const sp_key *key);
SP_API void sp_test_poly_mul(uint16_t out[256], const uint16_t a[256], const uint16_t b[256]);
#endif
#endif
