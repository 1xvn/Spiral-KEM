#[cfg(test)]
mod tests {
    use hmac::{KeyInit, Mac, Hmac, HmacReset, SimpleHmac, SimpleHmacReset};
    use hmac::digest::FixedOutputReset;
    use sha2::{Sha256, Sha512};
    fn decode(hex: &str) -> Vec<u8> {
        hex.as_bytes().chunks_exact(2).map(|s| u8::from_str_radix(std::str::from_utf8(s).unwrap(),16).unwrap()).collect()
    }
    fn check<M: KeyInit + Mac>(key: &[u8], input: &[u8], expected: &[u8]) {
        let mut mac = M::new_from_slice(key).unwrap();
        Mac::update(&mut mac, input);
        assert_eq!(&mac.finalize().into_bytes()[..], expected);
    }
    fn check_reset<M: KeyInit + Mac + FixedOutputReset>(key: &[u8], input: &[u8], expected: &[u8]) {
        let mut mac = M::new_from_slice(key).unwrap();
        for _ in 0..2 {
            Mac::update(&mut mac, input);
            assert_eq!(&mac.finalize_reset().into_bytes()[..], expected);
        }
    }
    #[test]
    fn all_four_variants_preserve_rfc4231_short_and_long_key_outputs() {
        for (key, input, sha256, sha512) in [
            (vec![0x0b;20], b"Hi There".as_slice(), "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"),
            (vec![0xaa;131], b"Test Using Larger Than Block-Size Key - Hash Key First".as_slice(), "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54", "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352 6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598")
        ] {
            let a=decode(sha256);let b=decode(&sha512.replace(' ',""));
            check::<Hmac<Sha256>>(&key,input,&a);check::<SimpleHmac<Sha256>>(&key,input,&a);
            check::<Hmac<Sha512>>(&key,input,&b);check::<SimpleHmac<Sha512>>(&key,input,&b);
            check::<HmacReset<Sha256>>(&key,input,&a);check::<SimpleHmacReset<Sha256>>(&key,input,&a);
            check::<HmacReset<Sha512>>(&key,input,&b);check::<SimpleHmacReset<Sha512>>(&key,input,&b);
            check_reset::<HmacReset<Sha256>>(&key,input,&a);check_reset::<SimpleHmacReset<Sha256>>(&key,input,&a);
            check_reset::<HmacReset<Sha512>>(&key,input,&b);check_reset::<SimpleHmacReset<Sha512>>(&key,input,&b);
        }
    }
}
