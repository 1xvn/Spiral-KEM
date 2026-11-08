# Inputs and scope of the temporary secret copy design

The target repository revision is `47c80c75cc93934836b2893905752fb3f13a0c23`, which is also the starting point of the new design branch.
We prepared only a derived design, without modifying executable sources or the original OCI/WSL evidence.
Target drift is `none`. This work is neither a repository-wide security scan nor a fix for a confirmed vulnerability.

The input collection SHA-256 is `53d3287b300e4c39a5cee0347b1ff19710d1ce25575657418a874603246bf944`. For `evidence/input-inventory.json`,
we serialized its sorted path/hash array as UTF-8 compact JSON(sort_keys=True, separators=(',', ':')),
then hashing it. We identified 27 logical inputs, 13 Git files, and 9 crate archives.
Dependency archive checksums were checked against both lockfiles, and the bytes of 170 Rust/Cargo source files were
compared with the original archives. These are integrity verification counts, not evidence that security audits of all 170 files were completed.

| ID | Input name | Directly inspected evidence |
|---|---|---|
| app-owners | Application key owners and key schedule | schedule.rs, identity.rs, secret.rs and existing regressions |
| hash-scratch | digest fixed-output temporaries | CtOutWrapper full_res and SHA output paths |
| hmac-scratch | HMAC pad/inner hash | HmacCore and long-key handling, Simple/Reset boundaries |
| hkdf-scratch | HKDF output/prev | One-block production calls and multiblock public API |
| signing-nonce | Ed25519 seed digest/nonce | High-level try_sign and internal raw_sign |
| backend-scratch | Intermediate scalar/point multiplication copies | reduction limbs, radix digits and Copy contract |
| arm-traces | Actual OCI ARM collection records | 70 functional tests and 160 collection runs; approval remains incomplete |
| api-probe | Output type compilation control | Positive control exit 0, Array:Zeroize control E0277 exit 101 |

Detailed input hashes are in `evidence/source-manifest.json`. Compilation controls were performed in a separate
synthetic crate; they did not implement wire/signature/erasure patches or measure actual wipes.
Only working paths in the retained compiler logs were normalized; original hashes remain in the result JSON.

The applied skill is codex-security:propose-security-hardening. Its shared reference
`../../references/artifact-storage.md`, in the provided cloud skill resources and local searches,
could not be opened. We kept input evidence read-only and used `hardening/secret-copies-20261108/` to
separate derived material in a conservative storage approach. We read and applied proposal-format.md.
