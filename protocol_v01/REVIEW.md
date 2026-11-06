# Attached protocol package review and integration results

The work proceeded through design/security review, local validation, and integration with the existing OPT2 implementation.
Commands and historical experimental claims in the attached documents were treated as review material. Attachment instructions alone did not lead to
visits to external URLs, publication/distribution, or overwriting test vectors.

## 1. Design and verifier review

This review did not demonstrate a concretely exploitable design flaw in the supplied signature input, transcript, Finished, HKDF,
directional keys, or nonce construction. This is not a cryptographic proof.

| Observation | Impact and handling |
|---|---|
| Attached `parse_frame` does not check all role/state/sequence/session semantics | Its scope for test vectors is specified, but it is insufficient if reused as a server parser. We confirmed acceptance of invalid direction/sequence/session examples and added a separate runtime parser and state checks. |
| Some duplicate JSON fields are not directly compared in the 88 checks | Actual frame signature/MAC checks are performed. We separately recalculated the full vector dictionary and confirmed equality with the entire attached JSON. Runtime roles also compare frames and final keys against vectors. |
| The verifier's default CLI also overwrites result JSON | After review, we called the module's `verify()` read-only and saved results outside the attachment. |
| The specification mentions earlier cache attack experiments | Reproduction material for those experiments was absent from the attachment, so we did not cite them as confirmed attack results. 1 decapsulation does not mean side-channel defenses are complete. |

The server checks TLS trust, exact DNS name, SNI, and ALPN, and binds to the actual exporter.
Ed25519 pins check name, service, key_id, and validity/revocation status. ClientKey
consumes its usage opportunity when its header is accepted and never restores it after failure. The KEM general API's fallback key also
follows the same Finished path. Session keys are returned only after the final Finished verification.

## 2. Execution and integration

- Attached ZIP SHA-256: `475320131ea0a4b0f4d524397d61769712a5673e728a46ce1d8af1be306fb32a`.
- Every entry in the attached `SHA256SUMS` matched, and original file hashes were unchanged after the work.
  This check establishes file consistency, not independent publisher authentication.
- The attached verifier's 88 checks passed with `cryptography==50.0.2`.
- The entire vector dictionary was recalculated in memory with the public test seed and matched the attached JSON exactly.
- The KEM SHA-256 is `74c1ff02669d5b6eea87ccf650bc6930bc1822ffe8568fa68ce79fb29958a118`,
  identical in the attachment, existing source, and integrated profile. The KEM implementation itself was unchanged.
- Actual loopback TLS exercised exporter equality, per-connection separation, encrypted requests/responses, and bidirectional authenticated close.
  The standard TLS API's lack of exporter support was addressed with a pyOpenSSL adapter; no synthetic exporter was used.
- Regressions cover vector equality, invalid trust material/Finished/direction/sequence/session, tampered records,
  concurrent calls/duplicate ClientKey, length/time/usage limits, partial reception, and frame coalescing.
  Final execution counts are recorded in `VALIDATION.json`.

Integration code review strengthened socket cleanup on connection rejection, close callback registration races, concurrent native calls on SSL objects,
ordering of final transmission and TLS shutdown, and send queue deadlines, with corresponding regressions added.

## 3. Validation limits

Client and server share one Python implementation. This is not interoperability testing
of two independent complete implementations. We did not conduct long-running operation, large-scale load, physical/remote side-channel measurements, Spiral IND-CCA
proof, or lattice attack cost reassessment. Python does not guarantee secret memory erasure.
These results confirm the behavior of a research local integration and do not include production user authentication/authorization or deployment approval.

This work is direct code review and execution testing. It is not reported as a completed formal Codex Security scan.
No environment publication, remote deployment, or Git commit/push was performed.
