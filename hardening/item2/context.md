# Item 2 design context

Source root: /workspace/Spiral-KEM
Target revision: 7c859d926b062c4ff08a0f31eeeec3596e21095a
Evidence drift: none for listed source and experiment files at inspection.
Mode: direct source and experiment collection; no sealed scan or new vulnerability claim.
User intent: upload latest test evidence first (done), then design item2; external researcher contact deferred.
Artifact status: derived design only. No native implementation or toolchain installation.
The common plugin artifact-storage reference could not be retrieved; this workspace draft uses a sibling hardening directory outside the code and experiment input collections.

| ID | Evidence | Path | Lines | SHA256 |
|---|---|---|---|---|
| bigint | Python large-integer polynomial arithmetic | `code/opt2/spiral_kem_toy_v031_opt2.py` | 479–508 | `74c1ff02669d5b6eea87ccf650bc6930bc1822ffe8568fa68ce79fb29958a118` |
| secret-flow | Message and secret coefficient processing | `code/opt2/spiral_kem_toy_v031_opt2.py` | 216–248;372–382;581–618 | `74c1ff02669d5b6eea87ccf650bc6930bc1822ffe8568fa68ce79fb29958a118` |
| python-keys | Shared secret and derived key transfer | `protocol_v01/handshake.py` | 42–49;284–302 | `5e86ee9278db82115f953eb06cca1cf54998149c55459d3021ffa9562fd025ce` |
| cleanup | Record key ownership and reference release | `protocol_v01/records.py` | 35–50;83–92;128–130;193–195 | `443006d2efb19da0f302a4c29677360a5b848fe39fc183bb4984831f62cfb5dd` |
| timing | 24,000 exploratory timing diagnostics | `protocol_v01/validation/results/timing.json` | whole file | `e125708c8a34e58c1ccab9023f34a99cb9f231bb87c5a8e5f2151235a9415d3b` |
| compatibility | Protocol v0.1 byte contract | `protocol_v01/SPEC_v0.1.md` | whole file | `7a8b12b0238da93048e296320b6b04aac9e2dbc9014a381b76e5d904e57d1745` |
| fixture | Public fixed protocol vectors | `protocol_v01/tests/fixtures/test_vectors_v0.1.json` | whole file | `b556ca8741a649dfe3346d2033a2685492470beedbc601dbb36877f4c5881ee8` |
| regression | Evidence from 75 regression checks | `protocol_v01/validation/results/regression.json` | whole file | `7643629465a48f94f88313c6358c2ba9a4ebebe2d71dfc13a9b2f6b2a1ca9351` |

Additional source inspection: protocol_v01/channel.py and tls.py preserve send serialization, deadlines and TLS ownership.
Local notes were independently reviewed; they are drafting aids, not external expert review.
Rust/Cargo were not available in PATH; neither was installed for this design.
