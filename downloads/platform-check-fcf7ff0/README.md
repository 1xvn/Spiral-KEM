# OCI·WSL validation bundle download

The same validation bundle is retained on GitHub as a reproducible download.
Source commit is `fcf7ff07ecba260f6b446baa7f1efd55bbe11ec2`; the file is byte-for-byte identical to the original bundle.

**[Download validation bundle](Spiral-platform-check-fcf7ff0.tar.gz?raw=true)**

Click the link in a browser logged into GitHub, or use the archive file page's
**Download raw file** button. Filename: `Spiral-platform-check-fcf7ff0.tar.gz`.

SHA-256:

```text
690dcfa32354be92a2cb93f65b40172e920c5f4aaca946d21a5e3131873f8e3b
```

Place the downloaded file in Ubuntu home on both OCI and WSL.

OCI ARM Ubuntu terminal:

```bash
cd "$HOME" &&
tar -xzf "$HOME/Spiral-platform-check-fcf7ff0.tar.gz" -C "$HOME" &&
python3 "$HOME/Spiral-platform-check-fcf7ff0/run_checks.py" --platform oci
```

WSL Ubuntu x86-64 terminal:

```bash
cd "$HOME" &&
tar -xzf "$HOME/Spiral-platform-check-fcf7ff0.tar.gz" -C "$HOME" &&
python3 "$HOME/Spiral-platform-check-fcf7ff0/run_checks.py" --platform wsl
```

At startup, verifies 603 source files and displays `Fixed source verified: fcf7ff07...`.
Runs validation sources inside the bundle regardless of the existing terminal working folder.
Both environments require Python 3.12, Rust 1.99.1, and C/OpenSSL tools from prior validation.
Pinned Python/Cargo dependencies may be downloaded.

Each run prints a new `.tar.gz` result file. Both successful and failed runs preserve logs and
source provenance. Original validation targets are Python 85·diagnostics 20·C9·Rust 70·documentation 6·TLS 35.
ARM ignored 0 and x86-64 ignored 5 are separate instrumentation targets excluded from normal functionality pass counts.

`bundle-validation.json` contains local Linux x86-64 results from running the bundle in a separate source folder,
and source-tampering rejection controls. It does not establish OCI/WSL completion or overall memory/constant-time/cryptographic security
approval. This download branch delivers files and contains no cryptographic implementation changes.
