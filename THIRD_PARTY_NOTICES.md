# Third-party materials

The root `LICENSE` covers only original materials owned by 1xvn. It does not
relicense third-party code or override permissions granted by its authors.
Existing copyright notices, license texts, provenance records, and applicable
terms remain in force, including for locally patched copies.

| Included component | Applicable license | License location |
| --- | --- | --- |
| RustCrypto digest | MIT OR Apache-2.0 | `third_party/rustcrypto/digest/LICENSE-MIT`, `LICENSE-APACHE` |
| RustCrypto hmac | MIT OR Apache-2.0 | `third_party/rustcrypto/hmac/LICENSE-MIT`, `LICENSE-APACHE` |
| RustCrypto hkdf | MIT OR Apache-2.0 | `third_party/rustcrypto/hkdf/LICENSE-MIT`, `LICENSE-APACHE` |
| curve25519-dalek | BSD-3-Clause | `third_party/rustcrypto/curve25519-dalek/LICENSE` |
| ed25519-dalek | BSD-3-Clause | `third_party/rustcrypto/ed25519-dalek/LICENSE` |
| Captured Rust standard-library source | MIT OR Apache-2.0 | `protocol_rust/evidence/secret_memory_20261108/stdlib-source/LICENSE-MIT`, `LICENSE-APACHE` |

Patch provenance is recorded in `third_party/rustcrypto/upstream-provenance.json`
and its patch manifest. Other dependencies, embedded archives, fixtures, and
reference materials retain their respective notices and upstream terms; the
table is an inventory of the directly inspected license files, not an exhaustive
relicensing statement for every dependency. Public availability of an archive
alone does not establish permission to reuse all of its contents.
