//! Compatibility checks for local temporary-output ownership changes.
use hkdf::{GenericHkdf, HmacImpl};
use hmac::{Hmac, SimpleHmac};
use sha2::Sha256;

fn rfc5869_case_one<H: HmacImpl>() {
    let ikm = [0x0b; 22];
    let salt = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
    let expected_prk = [
        0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf,
        0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
        0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
        0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5,
    ];
    let expected_okm = [
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
        0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
        0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
        0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
        0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
        0x58, 0x65,
    ];
    let (prk, extracted) = GenericHkdf::<H>::extract(Some(&salt), &ikm);
    assert_eq!(prk.as_slice(), expected_prk);
    let mut output = [0; 42];
    extracted.expand(&info, &mut output).unwrap();
    assert_eq!(output, expected_okm);

    let constructed = GenericHkdf::<H>::new(Some(&salt), &ikm);
    constructed
        .expand_multi_info(&[&info[..3], &info[3..]], &mut output)
        .unwrap();
    assert_eq!(output, expected_okm);
}

#[test]
fn extract_constructor_and_split_info_preserve_rfc5869_case_one() {
    rfc5869_case_one::<Hmac<Sha256>>();
    rfc5869_case_one::<SimpleHmac<Sha256>>();
}

fn boundaries<H: HmacImpl>() {
    let hkdf = GenericHkdf::<H>::new(None, b"public boundary test");
    let mut full = [0; 255 * 32];
    hkdf.expand(b"public info", &mut full).unwrap();
    for length in [0, 1, 4, 32, 33, 42, full.len()] {
        let mut out = vec![0xa5; length];
        hkdf.expand_multi_info(&[b"public ", b"info"], &mut out).unwrap();
        assert_eq!(out, full[..length]);
    }
    let mut oversized = [0xa5; 255 * 32 + 1];
    assert!(hkdf.expand(b"public info", &mut oversized).is_err());
    assert!(oversized.iter().all(|byte| *byte == 0xa5));
    assert!(GenericHkdf::<H>::from_prk(&[7; 31]).is_err());
}

#[test]
fn generic_lengths_and_rejections_are_unchanged() {
    boundaries::<Hmac<Sha256>>();
    boundaries::<SimpleHmac<Sha256>>();
}
