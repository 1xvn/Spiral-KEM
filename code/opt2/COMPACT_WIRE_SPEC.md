# SKW1 v1: lossless transport encoding

SKW1 is a transport wrapper for the Spiral v0.3 KEM. It does not change DOMAIN, SHAKE framing, canonical 16-bit public-key/ciphertext inputs to internal hashes, message/randomness lengths, or mathematical parameters. The default KEM API continues to use its original object types.

## Header: exactly 8 bytes

| Offset | Length | Value |
| --- | ---: | --- |
| 0 | 4 | ASCII `SKW1`; the final `1` identifies this wire-format version |
| 4 | 1 | `P` for public key or `C` for ciphertext |
| 5 | 1 | Profile ID |
| 6 | 2 | Reserved; exactly `00 00` |

| Profile ID | n | k | q | eta | Shared-key bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 | 8 | 2 | 3329 | 1 | 32 |
| 2 | 16 | 2 | 3329 | 1 | 32 |
| 3 | 32 | 2 | 3329 | 1 | 32 |
| 4 | 64 | 2 | 3329 | 1 | 32 |
| 5 | 128 | 2 | 3329 | 1 | 32 |
| 6 | 256 | 2 | 3329 | 1 | 32 |

The default is ID 6. Reduced profiles require explicit `lab_mode`. Receivers accept only headers matching their own profile and reject unknown versions, kinds, profiles or reserved bits.

## Two coefficients per three bytes

Canonical coefficients satisfy `0 <= a,b < 3329`. Concatenate their 12-bit representations with the lower-index coefficient first:

```text
byte0 = a & 255
byte1 = (a >> 8) | ((b & 15) << 4)
byte2 = b >> 4
```

An independent equivalent is `sum(c[i] << (12*i))` encoded as `n*3/2` little-endian bytes. No coefficient information is discarded. All supported `n` values are even, so there are no leftover padding bits. Decoded values 3329..4095 are rejected, not reduced modulo q.

A public-key payload contains the 32-byte `matrix_seed`, then `t[0],t[1]`. A ciphertext contains `u[0],u[1],v`. Polynomial coefficient order matches the legacy format. Each polynomial occupies `n*3/2` bytes.

| Default n=256 | Payload | Total including header |
| --- | ---: | ---: |
| Public key | 32+2*384=800 | 808 bytes |
| Ciphertext | 3*384=1152 | 1160 bytes |

Readers require the exact `bytes` type, complete length and header before unpacking and checking coefficient bounds. Truncation and trailing bytes are rejected. Legacy 16-bit and SKW1 formats have separate explicit APIs; automatic format guessing is not supported.

This codec provides neither peer authentication nor a security proof for the underlying KEM.
