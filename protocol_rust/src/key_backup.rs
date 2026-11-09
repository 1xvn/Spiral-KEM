//! Encrypted, path-based backup of authentication seeds and TLS private PEM.
//!
//! Every input and output uses the protected private-file boundary. Restore
//! authenticates the envelope and checks a separately supplied public identity
//! before publishing a new file. Returned values contain public digests only.
#![forbid(unsafe_code)]

use crate::{keyfiles, secret::Secret, transport, Error, Result};
use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    ChaCha20Poly1305, Nonce, Tag,
};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use std::{fs::File, io::Read, path::Path};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"SPBKUP00";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 58;
const TAG_LEN: usize = 16;

/// The private-file content and public identity represented by a backup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyKind {
    AuthSeed,
    TlsPem,
}
impl KeyKind {
    fn tag(self) -> u8 {
        match self {
            Self::AuthSeed => 1,
            Self::TlsPem => 2,
        }
    }
    fn max_len(self) -> usize {
        match self {
            Self::AuthSeed => 32,
            Self::TlsPem => transport::MAX_TLS_PEM,
        }
    }
    fn validate_len(self, len: usize) -> Result<()> {
        if match self {
            Self::AuthSeed => len == 32,
            Self::TlsPem => (1..=transport::MAX_TLS_PEM).contains(&len),
        } {
            Ok(())
        } else {
            Err(Error::Input)
        }
    }
}

/// Generate a 32-byte OS-random wrapping key in a new private file.
/// Existing names are never replaced. A post-publication sync error can leave
/// the final file present, as documented by the private-file writer.
pub fn generate_recovery_key(path: &Path) -> Result<()> {
    let mut key = Secret::<32>::zeros();
    getrandom::getrandom(key.bytes_mut()).map_err(|_| Error::Crypto)?;
    keyfiles::write_new_private(path, key.bytes())
}

/// SHA-256 of the raw Ed25519 public key, or of the TLS key's RFC 5280 DER SPKI.
pub fn public_fingerprint(kind: KeyKind, path: &Path) -> Result<[u8; 32]> {
    let mut plaintext = Zeroizing::new(vec![0; kind.max_len()]);
    let used = read_private_bounded(path, &mut plaintext)?;
    kind.validate_len(used)?;
    fingerprint(kind, &plaintext[..used])
}

/// Encrypt the original private-file bytes and atomically publish a new backup.
/// A fresh OS-random nonce is generated for every backup. An authentication seed
/// equal to the wrapping key is rejected to prevent accidental self-encryption.
pub fn backup(
    kind: KeyKind,
    source: &Path,
    recovery_key: &Path,
    destination: &Path,
) -> Result<[u8; 32]> {
    let key = read_recovery_key(recovery_key)?;
    // The initialized allocation never grows, and plaintext is encrypted where
    // it was read. Its full allocation is erased on every exit.
    let mut envelope = Zeroizing::new(vec![0; HEADER_LEN + kind.max_len() + TAG_LEN]);
    let used = read_private_bounded(source, &mut envelope[HEADER_LEN..][..kind.max_len()])?;
    kind.validate_len(used)?;
    reject_self_encryption(kind, &envelope[HEADER_LEN..][..used], &key)?;
    let public = fingerprint(kind, &envelope[HEADER_LEN..][..used])?;
    let (header, body) = envelope.split_at_mut(HEADER_LEN);
    header[..8].copy_from_slice(MAGIC);
    header[8] = VERSION;
    header[9] = kind.tag();
    getrandom::getrandom(&mut header[10..22]).map_err(|_| Error::Crypto)?;
    header[22..54].copy_from_slice(&public);
    header[54..58].copy_from_slice(&(used as u32).to_be_bytes());
    let cipher = ChaCha20Poly1305::new_from_slice(key.bytes()).map_err(|_| Error::Crypto)?;
    let tag = cipher
        .encrypt_in_place_detached(
            Nonce::from_slice(&header[10..22]),
            header,
            &mut body[..used],
        )
        .map_err(|_| Error::Crypto)?;
    body[used..used + TAG_LEN].copy_from_slice(tag.as_ref());
    keyfiles::write_new_private(destination, &envelope[..HEADER_LEN + used + TAG_LEN])?;
    Ok(public)
}

/// Authenticate, validate the recovered public identity, then publish a new file.
/// `expected_fingerprint` must come from a separately retained public identity.
/// Wrong keys, malformed envelopes, identity mismatches and existing destinations
/// fail without replacing a destination.
pub fn restore(
    kind: KeyKind,
    backup_path: &Path,
    recovery_key: &Path,
    destination: &Path,
    expected_fingerprint: [u8; 32],
) -> Result<[u8; 32]> {
    let key = read_recovery_key(recovery_key)?;
    let mut file = keyfiles::open_private(backup_path)?;
    if file.metadata()?.len() > (HEADER_LEN + kind.max_len() + TAG_LEN) as u64 {
        return Err(Error::Input);
    }
    let mut header = [0; HEADER_LEN];
    file.read_exact(&mut header)?;
    let used = parse_header(kind, &header)?;
    let mut body = Zeroizing::new(vec![0; used + TAG_LEN]);
    file.read_exact(&mut body)?;
    require_eof(&mut file)?;
    let (plaintext, tag) = body.split_at_mut(used);
    let cipher = ChaCha20Poly1305::new_from_slice(key.bytes()).map_err(|_| Error::Crypto)?;
    cipher
        .decrypt_in_place_detached(
            Nonce::from_slice(&header[10..22]),
            &header,
            plaintext,
            Tag::from_slice(tag),
        )
        .map_err(|_| Error::Authentication)?;
    reject_self_encryption(kind, plaintext, &key)?;
    let public = fingerprint(kind, plaintext)?;
    if public.as_slice() != &header[22..54] || public != expected_fingerprint {
        return Err(Error::Authentication);
    }
    keyfiles::write_new_private(destination, plaintext)?;
    Ok(public)
}

fn read_recovery_key(path: &Path) -> Result<Secret<32>> {
    let mut file = keyfiles::open_private(path)?;
    let mut key = Secret::<32>::zeros();
    file.read_exact(key.bytes_mut())?;
    require_eof(&mut file)?;
    Ok(key)
}

fn require_eof(file: &mut File) -> Result<()> {
    let mut extra = Zeroizing::new([0; 1]);
    if file.read(extra.as_mut())? != 0 {
        return Err(Error::Input);
    }
    Ok(())
}

fn read_private_bounded(path: &Path, storage: &mut [u8]) -> Result<usize> {
    let mut file = keyfiles::open_private(path)?;
    if file.metadata()?.len() > storage.len() as u64 {
        return Err(Error::Input);
    }
    let mut used = 0;
    while used < storage.len() {
        let read = file.read(&mut storage[used..])?;
        if read == 0 {
            return Ok(used);
        }
        used += read;
    }
    require_eof(&mut file)?;
    Ok(used)
}

fn parse_header(kind: KeyKind, header: &[u8; HEADER_LEN]) -> Result<usize> {
    if &header[..8] != MAGIC || header[8] != VERSION || header[9] != kind.tag() {
        return Err(Error::Input);
    }
    let used = u32::from_be_bytes(header[54..58].try_into().map_err(|_| Error::Input)?) as usize;
    kind.validate_len(used)?;
    Ok(used)
}

fn reject_self_encryption(kind: KeyKind, plaintext: &[u8], key: &Secret<32>) -> Result<()> {
    if kind == KeyKind::AuthSeed && bool::from(plaintext.ct_eq(key.bytes())) {
        return Err(Error::Input);
    }
    Ok(())
}

fn fingerprint(kind: KeyKind, plaintext: &[u8]) -> Result<[u8; 32]> {
    kind.validate_len(plaintext.len())?;
    match kind {
        KeyKind::AuthSeed => {
            let seed = plaintext.try_into().map_err(|_| Error::Input)?;
            let signing = SigningKey::from_bytes(seed);
            Ok(Sha256::digest(signing.verifying_key().as_bytes()).into())
        }
        KeyKind::TlsPem => {
            let der = transport::parse_one_private_key(plaintext)?;
            let signing = rustls::crypto::ring::sign::any_supported_type(der.der())
                .map_err(|_| Error::Input)?;
            let spki = signing.public_key().ok_or(Error::Input)?;
            Ok(Sha256::digest(spki.as_ref()).into())
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::{
        ffi::OsString,
        fs::{self, DirBuilder, OpenOptions, Permissions},
        io::Write,
        os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        path::PathBuf,
    };

    // A public test fixture: PKCS#8 Ed25519 with seed [7; 32].
    const TLS_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----\n\
MC4CAQAwBQYDK2VwBCIEIAcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcH\n\
-----END PRIVATE KEY-----\n";

    struct Fixture {
        path: PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            let mut random = [0; 16];
            getrandom::getrandom(&mut random).unwrap();
            let path = std::env::temp_dir().join(format!(
                "spiral-backup-{}-{}",
                std::process::id(),
                hex::encode(random)
            ));
            DirBuilder::new().mode(0o700).create(&path).unwrap();
            fs::set_permissions(&path, Permissions::from_mode(0o700)).unwrap();
            Self { path }
        }
        fn name(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }
        fn key(&self, name: &str, bytes: &[u8]) -> PathBuf {
            let path = self.name(name);
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .unwrap();
            file.set_permissions(Permissions::from_mode(0o600)).unwrap();
            file.write_all(bytes).unwrap();
            path
        }
        fn entries(&self) -> Vec<OsString> {
            let mut entries = fs::read_dir(&self.path)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<Vec<_>>();
            entries.sort();
            entries
        }
        fn auth_backup(&self) -> (PathBuf, PathBuf, [u8; 32]) {
            let source = self.key("auth", &[42; 32]);
            let recovery = self.key("recovery", &[8; 32]);
            let encrypted = self.name("backup");
            let digest = backup(KeyKind::AuthSeed, &source, &recovery, &encrypted).unwrap();
            (encrypted, recovery, digest)
        }
        fn reject_restore(
            &self,
            kind: KeyKind,
            encrypted: &Path,
            recovery: &Path,
            expected: [u8; 32],
        ) {
            let before = self.entries();
            let destination = self.name("rejected");
            assert!(restore(kind, encrypted, recovery, &destination, expected).is_err());
            assert!(!destination.exists());
            assert_eq!(self.entries(), before);
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::set_permissions(&self.path, Permissions::from_mode(0o700));
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn authenticated_fixture(
        kind: KeyKind,
        plaintext: &[u8],
        claimed_fingerprint: [u8; 32],
        wrapping: &[u8; 32],
    ) -> Zeroizing<Vec<u8>> {
        let mut envelope = Zeroizing::new(vec![0; HEADER_LEN + plaintext.len() + TAG_LEN]);
        let (header, body) = envelope.split_at_mut(HEADER_LEN);
        header[..8].copy_from_slice(MAGIC);
        header[8] = VERSION;
        header[9] = kind.tag();
        header[10..22].fill(9);
        header[22..54].copy_from_slice(&claimed_fingerprint);
        header[54..58].copy_from_slice(&(plaintext.len() as u32).to_be_bytes());
        body[..plaintext.len()].copy_from_slice(plaintext);
        let cipher = ChaCha20Poly1305::new_from_slice(wrapping).unwrap();
        let tag = cipher
            .encrypt_in_place_detached(
                Nonce::from_slice(&header[10..22]),
                header,
                &mut body[..plaintext.len()],
            )
            .unwrap();
        body[plaintext.len()..].copy_from_slice(tag.as_ref());
        envelope
    }

    #[test]
    fn recovery_generation_is_private_random_and_no_replace() {
        let fixture = Fixture::new();
        let first = fixture.name("first");
        let second = fixture.name("second");
        generate_recovery_key(&first).unwrap();
        generate_recovery_key(&second).unwrap();
        let first_bytes = Zeroizing::new(fs::read(&first).unwrap());
        let second_bytes = Zeroizing::new(fs::read(&second).unwrap());
        assert!(first_bytes.len() == 32 && second_bytes.len() == 32);
        assert!(first_bytes != second_bytes);
        let metadata = fs::metadata(&first).unwrap();
        assert_eq!(metadata.mode() & 0o7777, 0o600);
        assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
        assert_eq!(metadata.nlink(), 1);
        let before = fixture.entries();
        assert!(generate_recovery_key(&first).is_err());
        assert!(fs::read(&first).unwrap().as_slice() == first_bytes.as_slice());
        assert_eq!(fixture.entries(), before);
    }

    #[test]
    fn auth_round_trip_and_public_digest() {
        let fixture = Fixture::new();
        let (encrypted, recovery, digest) = fixture.auth_backup();
        let identity = crate::identity::ServerIdentity::load(&fixture.name("auth")).unwrap();
        let expected: [u8; 32] = Sha256::digest(identity.public_key()).into();
        assert_eq!(digest, expected);
        assert_eq!(
            public_fingerprint(KeyKind::AuthSeed, &fixture.name("auth")).unwrap(),
            expected
        );
        let destination = fixture.name("restored");
        assert_eq!(
            restore(KeyKind::AuthSeed, &encrypted, &recovery, &destination, expected).unwrap(),
            expected
        );
        assert!(fs::read(&destination).unwrap().as_slice() == [42; 32]);
        assert_eq!(fs::metadata(&destination).unwrap().mode() & 0o7777, 0o600);
        let bytes = fs::read(encrypted).unwrap();
        assert_eq!(bytes.len(), 106);
        assert_eq!(&bytes[..8], MAGIC);
        assert_eq!(bytes[8], 1);
        assert_eq!(bytes[9], 1);
        assert_eq!(&bytes[22..54], &expected);
        assert_eq!(&bytes[54..58], &32u32.to_be_bytes());
        // These are the only public backup results; no secret owner is exposed.
        let _: fn(KeyKind, &Path) -> Result<[u8; 32]> = public_fingerprint;
        let _: fn(KeyKind, &Path, &Path, &Path) -> Result<[u8; 32]> = backup;
        let _: fn(KeyKind, &Path, &Path, &Path, [u8; 32]) -> Result<[u8; 32]> = restore;
        static_assertions::assert_not_impl_any!(Secret<32>: Clone, Copy, std::fmt::Debug);
    }

    #[test]
    fn tls_round_trip_preserves_original_pem_and_spki_digest() {
        let fixture = Fixture::new();
        let mut pem = Zeroizing::new(b"public fixture preamble\n".to_vec());
        pem.extend_from_slice(TLS_PEM);
        pem.extend_from_slice(b"\npublic fixture postamble\n");
        let source = fixture.key("tls", &pem);
        let recovery = fixture.key("recovery", &[8; 32]);
        let encrypted = fixture.name("backup");
        // Independent RFC 8410 SPKI construction, without the rustls encoder.
        let mut spki = hex::decode("302a300506032b6570032100").unwrap();
        spki.extend_from_slice(
            SigningKey::from_bytes(&[7; 32])
                .verifying_key()
                .as_bytes(),
        );
        let expected: [u8; 32] = Sha256::digest(&spki).into();
        assert_eq!(public_fingerprint(KeyKind::TlsPem, &source).unwrap(), expected);
        assert_eq!(
            backup(KeyKind::TlsPem, &source, &recovery, &encrypted).unwrap(),
            expected
        );
        let destination = fixture.name("restored");
        assert_eq!(
            restore(KeyKind::TlsPem, &encrypted, &recovery, &destination, expected).unwrap(),
            expected
        );
        assert!(fs::read(destination).unwrap().as_slice() == pem.as_slice());
        assert_eq!(
            fs::metadata(encrypted).unwrap().len() as usize,
            HEADER_LEN + pem.len() + TAG_LEN
        );
    }

    #[test]
    fn fresh_nonces_for_repeated_backups() {
        let fixture = Fixture::new();
        let (first, recovery, digest) = fixture.auth_backup();
        let second = fixture.name("second");
        assert_eq!(
            backup(KeyKind::AuthSeed, &fixture.name("auth"), &recovery, &second).unwrap(),
            digest
        );
        let first = fs::read(first).unwrap();
        let second = fs::read(second).unwrap();
        assert_ne!(&first[10..22], &second[10..22]);
        assert_ne!(&first[HEADER_LEN..], &second[HEADER_LEN..]);
    }

    #[test]
    fn wrong_key_and_expected_identity_leave_no_destination() {
        let fixture = Fixture::new();
        let (encrypted, recovery, digest) = fixture.auth_backup();
        let wrong = fixture.key("wrong-recovery", &[9; 32]);
        fixture.reject_restore(KeyKind::AuthSeed, &encrypted, &wrong, digest);
        let mut wrong_digest = digest;
        wrong_digest[0] ^= 1;
        fixture.reject_restore(KeyKind::AuthSeed, &encrypted, &recovery, wrong_digest);
        fixture.reject_restore(KeyKind::TlsPem, &encrypted, &recovery, digest);
    }

    #[test]
    fn every_envelope_byte_is_authenticated() {
        let fixture = Fixture::new();
        let (encrypted, recovery, digest) = fixture.auth_backup();
        let original = fs::read(&encrypted).unwrap();
        for index in 0..original.len() {
            let mut changed = original.clone();
            changed[index] ^= 1;
            fs::write(&encrypted, changed).unwrap();
            fixture.reject_restore(KeyKind::AuthSeed, &encrypted, &recovery, digest);
        }
    }

    #[test]
    fn unknown_format_kind_and_invalid_lengths_are_rejected() {
        let fixture = Fixture::new();
        let (encrypted, recovery, digest) = fixture.auth_backup();
        let original = fs::read(&encrypted).unwrap();
        for (offset, values) in [(8, &[0, 2, 255][..]), (9, &[0, 2, 3, 255][..])] {
            for value in values {
                let mut changed = original.clone();
                changed[offset] = *value;
                fs::write(&encrypted, changed).unwrap();
                fixture.reject_restore(KeyKind::AuthSeed, &encrypted, &recovery, digest);
            }
        }
        for length in [0u32, 1, 31, 33, 65_536, 65_537, u32::MAX] {
            let mut changed = original.clone();
            changed[54..58].copy_from_slice(&length.to_be_bytes());
            fs::write(&encrypted, changed).unwrap();
            fixture.reject_restore(KeyKind::AuthSeed, &encrypted, &recovery, digest);
        }
        let mut changed = original;
        changed[..8].copy_from_slice(b"UNKNOWN!");
        fs::write(&encrypted, changed).unwrap();
        fixture.reject_restore(KeyKind::AuthSeed, &encrypted, &recovery, digest);
    }

    #[test]
    fn truncated_and_trailing_envelopes_are_rejected() {
        let fixture = Fixture::new();
        let (encrypted, recovery, digest) = fixture.auth_backup();
        let original = fs::read(&encrypted).unwrap();
        for length in 0..original.len() {
            fs::write(&encrypted, &original[..length]).unwrap();
            fixture.reject_restore(KeyKind::AuthSeed, &encrypted, &recovery, digest);
        }
        let mut trailing = original;
        trailing.push(0);
        fs::write(&encrypted, trailing).unwrap();
        fixture.reject_restore(KeyKind::AuthSeed, &encrypted, &recovery, digest);
    }

    #[test]
    fn authenticated_plaintext_identity_must_match_header_and_external() {
        let fixture = Fixture::new();
        let recovery = fixture.key("recovery", &[8; 32]);
        let first = fingerprint(KeyKind::AuthSeed, &[42; 32]).unwrap();
        let second = fingerprint(KeyKind::AuthSeed, &[43; 32]).unwrap();
        let envelope = authenticated_fixture(KeyKind::AuthSeed, &[43; 32], first, &[8; 32]);
        let encrypted = fixture.key("mismatch", &envelope);
        // Even the actual plaintext identity cannot override a false header.
        for expected in [first, second] {
            fixture.reject_restore(KeyKind::AuthSeed, &encrypted, &recovery, expected);
        }
        let tls_digest = fingerprint(KeyKind::TlsPem, TLS_PEM).unwrap();
        let invalid_pem = authenticated_fixture(KeyKind::TlsPem, b"not PEM", tls_digest, &[8; 32]);
        let invalid_pem = fixture.key("invalid-pem", &invalid_pem);
        fixture.reject_restore(KeyKind::TlsPem, &invalid_pem, &recovery, tls_digest);
    }

    #[test]
    fn auth_source_and_recovery_sizes_and_self_encryption_are_rejected() {
        let fixture = Fixture::new();
        let (encrypted, recovery, digest) = fixture.auth_backup();
        for length in [0, 1, 31, 33, 64] {
            let wrong_source = fixture.key(&format!("source-{length}"), &vec![42; length]);
            assert!(public_fingerprint(KeyKind::AuthSeed, &wrong_source).is_err());
            assert!(backup(
                KeyKind::AuthSeed,
                &wrong_source,
                &recovery,
                &fixture.name("rejected")
            )
            .is_err());
            let wrong_key = fixture.key(&format!("recovery-{length}"), &vec![8; length]);
            assert!(backup(
                KeyKind::AuthSeed,
                &fixture.name("auth"),
                &wrong_key,
                &fixture.name("rejected")
            )
            .is_err());
            fixture.reject_restore(KeyKind::AuthSeed, &encrypted, &wrong_key, digest);
        }
        assert!(backup(
            KeyKind::AuthSeed,
            &recovery,
            &recovery,
            &fixture.name("rejected")
        )
        .is_err());
        let same_digest = fingerprint(KeyKind::AuthSeed, &[8; 32]).unwrap();
        let self_encrypted =
            authenticated_fixture(KeyKind::AuthSeed, &[8; 32], same_digest, &[8; 32]);
        let self_encrypted = fixture.key("self-encrypted", &self_encrypted);
        fixture.reject_restore(KeyKind::AuthSeed, &self_encrypted, &recovery, same_digest);
        assert!(!fixture.name("rejected").exists());
    }

    #[test]
    fn tls_size_bounds_apply_to_source_and_restored_payload() {
        let fixture = Fixture::new();
        let recovery = fixture.key("recovery", &[8; 32]);
        let mut pem = Zeroizing::new(vec![b'\n'; transport::MAX_TLS_PEM]);
        pem[..TLS_PEM.len()].copy_from_slice(TLS_PEM);
        let source = fixture.key("at-limit", &pem);
        let expected = public_fingerprint(KeyKind::TlsPem, &source).unwrap();
        let encrypted = fixture.name("backup");
        assert_eq!(
            backup(KeyKind::TlsPem, &source, &recovery, &encrypted).unwrap(),
            expected
        );
        assert_eq!(fs::metadata(&encrypted).unwrap().len(), 65_610);
        let restored = fixture.name("restored");
        assert_eq!(
            restore(KeyKind::TlsPem, &encrypted, &recovery, &restored, expected).unwrap(),
            expected
        );
        assert!(fs::read(restored).unwrap().as_slice() == pem.as_slice());
        let mut oversized = Zeroizing::new(vec![b'\n'; transport::MAX_TLS_PEM + 1]);
        oversized[..TLS_PEM.len()].copy_from_slice(TLS_PEM);
        let oversized_source = fixture.key("oversized", &oversized);
        assert!(public_fingerprint(KeyKind::TlsPem, &oversized_source).is_err());
        assert!(backup(
            KeyKind::TlsPem,
            &oversized_source,
            &recovery,
            &fixture.name("rejected")
        )
        .is_err());
        let oversized = authenticated_fixture(KeyKind::TlsPem, &oversized, expected, &[8; 32]);
        let oversized_backup = fixture.key("oversized-backup", &oversized);
        fixture.reject_restore(KeyKind::TlsPem, &oversized_backup, &recovery, expected);
        let empty_source = fixture.key("empty", b"");
        assert!(public_fingerprint(KeyKind::TlsPem, &empty_source).is_err());
        assert!(backup(
            KeyKind::TlsPem,
            &empty_source,
            &recovery,
            &fixture.name("rejected")
        )
        .is_err());
        let empty = authenticated_fixture(KeyKind::TlsPem, b"", expected, &[8; 32]);
        let empty_backup = fixture.key("empty-backup", &empty);
        fixture.reject_restore(KeyKind::TlsPem, &empty_backup, &recovery, expected);
    }

    #[test]
    fn tls_parser_policy_preserves_single_private_key() {
        let fixture = Fixture::new();
        let recovery = fixture.key("recovery", &[8; 32]);
        let mut duplicated = Zeroizing::new(TLS_PEM.to_vec());
        duplicated.extend_from_slice(TLS_PEM);
        let malformed = b"-----BEGIN PRIVATE KEY-----\n!!!\n-----END PRIVATE KEY-----\n";
        for (name, pem) in [
            ("duplicate", duplicated.as_slice()),
            ("malformed", malformed.as_slice()),
            ("no-key", b"only text".as_slice()),
        ] {
            let source = fixture.key(name, pem);
            assert!(public_fingerprint(KeyKind::TlsPem, &source).is_err());
            assert!(transport::load_tls_private_key(&source).is_err());
            assert!(backup(
                KeyKind::TlsPem,
                &source,
                &recovery,
                &fixture.name("rejected")
            )
            .is_err());
            let envelope = authenticated_fixture(KeyKind::TlsPem, pem, [0; 32], &[8; 32]);
            let encrypted = fixture.key(&format!("{name}-backup"), &envelope);
            fixture.reject_restore(KeyKind::TlsPem, &encrypted, &recovery, [0; 32]);
        }
        let mut certificate_and_key = Zeroizing::new(
            b"-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n".to_vec(),
        );
        certificate_and_key.extend_from_slice(TLS_PEM);
        let source = fixture.key("certificate-and-key", &certificate_and_key);
        assert_eq!(
            public_fingerprint(KeyKind::TlsPem, &source).unwrap(),
            fingerprint(KeyKind::TlsPem, TLS_PEM).unwrap()
        );
        // Existing loader retains its provider-ownership contract.
        let _der = Zeroizing::new(transport::load_tls_private_key(&source).unwrap());
    }

    #[test]
    fn existing_destinations_are_not_replaced() {
        let fixture = Fixture::new();
        let (encrypted, recovery, digest) = fixture.auth_backup();
        let destination = fixture.key("existing", b"existing private file");
        let original = Zeroizing::new(fs::read(&destination).unwrap());
        let before = fixture.entries();
        assert!(backup(
            KeyKind::AuthSeed,
            &fixture.name("auth"),
            &recovery,
            &destination
        )
        .is_err());
        assert!(restore(KeyKind::AuthSeed, &encrypted, &recovery, &destination, digest).is_err());
        assert!(fs::read(destination).unwrap().as_slice() == original.as_slice());
        assert_eq!(fixture.entries(), before);
    }
}
