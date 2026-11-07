//! Independent, test-only interpretations of the public v0.1 wire grammar.
//!
//! Keep these independent of the runtime parsers and their constants: the fuzz
//! targets use them to detect acceptance of malformed input as well as rejection
//! of valid input. They check syntax, not authentication or connection state.

/// Whether `data` is exactly one syntactically valid Spiral v0.1 frame.
pub fn frame_is_valid(data: &[u8]) -> bool {
    let Some(header) = data.get(..40) else {
        return false;
    };
    if &header[..6] != b"SPK1\0\x01" || header[10..12] != [0, 0] || header[7] > 1 {
        return false;
    }

    let kind = header[6];
    let expected_suite = if kind == 1 { [0, 0] } else { [0xf0, 1] };
    let zero_session = header[12..28].iter().all(|&byte| byte == 0);
    if header[8..10] != expected_suite || zero_session != (kind == 1) {
        return false;
    }

    let sequence = u64::from_be_bytes([
        header[28], header[29], header[30], header[31], header[32], header[33], header[34],
        header[35],
    ]);
    let length = u32::from_be_bytes([header[36], header[37], header[38], header[39]]) as usize;
    if data.len() - 40 != length {
        return false;
    }

    match kind {
        1 => header[7] == 0 && sequence == 0 && (75..=418).contains(&length),
        2 => header[7] == 1 && sequence == 0 && length == 940,
        3 => header[7] == 0 && sequence == 1 && length == 1192,
        4 => header[7] == 1 && sequence == 1 && length == 32,
        // The last record sequence is reserved for CLOSE in each direction.
        0x10 => sequence < (1 << 20) - 1 && (17..=16400).contains(&length),
        0x11 => sequence < (1 << 20) && length == 17,
        _ => false,
    }
}

fn take_prefix<'a>(remaining: &mut &'a [u8], length: usize) -> Option<&'a [u8]> {
    if length > remaining.len() {
        return None;
    }
    let (field, rest) = remaining.split_at(length);
    *remaining = rest;
    Some(field)
}

fn offered(remaining: &mut &[u8], required: u16) -> Option<()> {
    let count = usize::from(take_prefix(remaining, 1)?[0]);
    if !(1..=8).contains(&count) {
        return None;
    }
    let values = take_prefix(remaining, count * 2)?;
    let required = required.to_be_bytes();
    if !values.chunks_exact(2).any(|word| word == required)
        || values.chunks_exact(2).any(|word| word == [0, 0])
        // Lexicographic ordering of two-byte big-endian words is numeric order.
        || values
            .windows(4)
            .step_by(2)
            .any(|pair| pair[..2] >= pair[2..])
    {
        return None;
    }
    Some(())
}

fn lower_alphanumeric(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit()
}

/// Return the borrowed DNS name and service of an exactly valid ClientHello.
pub fn hello_fields(data: &[u8]) -> Option<(&str, &str)> {
    if !(75..=418).contains(&data.len()) {
        return None;
    }
    // Random and exporter binding are opaque, fixed-width byte strings.
    let mut remaining = &data[64..];
    offered(&mut remaining, 1)?;
    offered(&mut remaining, 0xf001)?;

    let name_length = take_prefix(&mut remaining, 2)?;
    let name_length = usize::from(u16::from_be_bytes([name_length[0], name_length[1]]));
    if !(1..=253).contains(&name_length) {
        return None;
    }
    let name_bytes = take_prefix(&mut remaining, name_length)?;
    for label in name_bytes.split(|&byte| byte == b'.') {
        if !(1..=63).contains(&label.len())
            || !lower_alphanumeric(label[0])
            || !lower_alphanumeric(label[label.len() - 1])
            || !label
                .iter()
                .all(|&byte| lower_alphanumeric(byte) || byte == b'-')
        {
            return None;
        }
    }
    let name = std::str::from_utf8(name_bytes).ok()?;
    if name.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }

    let service_length = usize::from(take_prefix(&mut remaining, 1)?[0]);
    if !(1..=64).contains(&service_length) {
        return None;
    }
    let service_bytes = take_prefix(&mut remaining, service_length)?;
    if !remaining.is_empty()
        || !lower_alphanumeric(service_bytes[0])
        || !service_bytes
            .iter()
            .all(|&byte| lower_alphanumeric(byte) || b"._/-".contains(&byte))
    {
        return None;
    }
    Some((name, std::str::from_utf8(service_bytes).ok()?))
}

#[cfg(test)]
mod tests {
    use super::{frame_is_valid, hello_fields};

    fn fixture_frame(name: &str) -> Vec<u8> {
        // The fixture is public JSON with hex strings; avoid introducing a JSON
        // or hex dependency into the standalone fuzz crate for these tests.
        let fixture = include_str!("../../protocol_v01/tests/fixtures/test_vectors_v0.1.json");
        let frames = fixture.split_once("\"frames\": {").unwrap().1;
        let key = format!("\"{name}\": \"");
        let encoded = frames
            .split_once(&key)
            .unwrap()
            .1
            .split('"')
            .next()
            .unwrap();
        assert_eq!(encoded.len() % 2, 0);
        encoded
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    fn frame(kind: u8, role: u8, sequence: u64, length: usize) -> Vec<u8> {
        let mut raw = vec![0; 40 + length];
        raw[..6].copy_from_slice(b"SPK1\0\x01");
        raw[6] = kind;
        raw[7] = role;
        if kind != 1 {
            raw[8..10].copy_from_slice(&[0xf0, 1]);
            raw[12..28].fill(0xa5);
        }
        raw[28..36].copy_from_slice(&sequence.to_be_bytes());
        raw[36..40].copy_from_slice(&(length as u32).to_be_bytes());
        raw
    }

    fn hello(name: &[u8], service: &[u8], versions: &[u16], suites: &[u16]) -> Vec<u8> {
        let mut raw = vec![0xa5; 64];
        for values in [versions, suites] {
            raw.push(values.len() as u8);
            for value in values {
                raw.extend_from_slice(&value.to_be_bytes());
            }
        }
        raw.extend_from_slice(&(name.len() as u16).to_be_bytes());
        raw.extend_from_slice(name);
        raw.push(service.len() as u8);
        raw.extend_from_slice(service);
        raw
    }

    #[test]
    fn public_frames_and_exact_consumption() {
        for name in [
            "client_hello",
            "server_hello",
            "client_key",
            "server_finished",
            "client_data",
            "client_close",
            "server_data",
            "server_close",
        ] {
            let raw = fixture_frame(name);
            assert!(frame_is_valid(&raw), "{name}");
            for end in 0..raw.len() {
                assert!(!frame_is_valid(&raw[..end]), "{name} truncated to {end}");
            }
            let mut trailing = raw;
            trailing.push(0);
            assert!(!frame_is_valid(&trailing), "{name} with trailing byte");
        }
        let raw = fixture_frame("client_hello");
        assert_eq!(
            hello_fields(&raw[40..]),
            Some(("spiral-lab.example", "spiral-research"))
        );
    }

    #[test]
    fn frame_kind_length_role_and_handshake_sequence_boundaries() {
        for (kind, role, sequence, min, max) in [
            (1, 0, 0, 75, 418),
            (2, 1, 0, 940, 940),
            (3, 0, 1, 1192, 1192),
            (4, 1, 1, 32, 32),
            (0x10, 0, 0, 17, 16400),
            (0x11, 1, 0, 17, 17),
        ] {
            for length in [min, max] {
                assert!(frame_is_valid(&frame(kind, role, sequence, length)));
            }
            for length in [min - 1, max + 1] {
                assert!(!frame_is_valid(&frame(kind, role, sequence, length)));
            }
            assert!(!frame_is_valid(&frame(kind, 2, sequence, min)));
            if kind < 0x10 {
                assert!(!frame_is_valid(&frame(kind, 1 - role, sequence, min)));
                assert!(!frame_is_valid(&frame(kind, role, sequence ^ 1, min)));
            } else {
                assert!(frame_is_valid(&frame(kind, 1 - role, sequence, min)));
            }
        }
        for kind in [0, 5, 0x0f, 0x12, 0xff] {
            assert!(!frame_is_valid(&frame(kind, 0, 0, 17)));
        }
        assert!(frame_is_valid(&frame(0x10, 0, (1 << 20) - 2, 17)));
        assert!(!frame_is_valid(&frame(0x10, 0, (1 << 20) - 1, 17)));
        assert!(frame_is_valid(&frame(0x11, 1, (1 << 20) - 1, 17)));
        for kind in [0x10, 0x11] {
            for sequence in [1 << 20, u64::MAX] {
                assert!(!frame_is_valid(&frame(kind, 0, sequence, 17)));
            }
        }
    }

    #[test]
    fn frame_constants_sessions_and_claimed_lengths() {
        for name in ["client_hello", "server_hello", "client_data"] {
            let raw = fixture_frame(name);
            for index in [0, 1, 2, 3, 4, 5, 8, 9, 10, 11] {
                let mut bad = raw.clone();
                bad[index] ^= 1;
                assert!(!frame_is_valid(&bad), "{name}, header byte {index}");
            }
            let mut bad = raw.clone();
            if bad[6] == 1 {
                bad[12] = 1;
            } else {
                bad[12..28].fill(0);
            }
            assert!(!frame_is_valid(&bad));
            for length in [0u32, 1, 0x7fff_ffff, u32::MAX] {
                let mut bad = raw.clone();
                bad[36..40].copy_from_slice(&length.to_be_bytes());
                assert!(!frame_is_valid(&bad));
            }
        }
    }

    #[test]
    fn hello_minimum_maximum_and_opaque_prefix() {
        let minimum = hello(b"a", b"b", &[1], &[0xf001]);
        assert_eq!(minimum.len(), 75);
        assert_eq!(hello_fields(&minimum), Some(("a", "b")));
        for index in 0..64 {
            let mut changed = minimum.clone();
            changed[index] ^= 0xff;
            assert_eq!(hello_fields(&changed), Some(("a", "b")));
        }

        let longest_name = [
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61),
        ]
        .join(".");
        let longest_service = "x".repeat(64);
        let maximum = hello(
            longest_name.as_bytes(),
            longest_service.as_bytes(),
            &[1, 2, 3, 4, 5, 6, 7, 8],
            &[1, 2, 3, 4, 5, 6, 7, 0xf001],
        );
        assert_eq!(maximum.len(), 418);
        assert_eq!(
            hello_fields(&maximum),
            Some((longest_name.as_str(), longest_service.as_str()))
        );
        let mut too_long = maximum;
        too_long.push(0);
        assert!(hello_fields(&too_long).is_none());
    }

    #[test]
    fn hello_offer_counts_order_nonzero_and_required_values() {
        for bad in [
            vec![],
            vec![0, 1],
            vec![1, 1],
            vec![2, 1],
            vec![2],
            (1..=9).collect(),
        ] {
            // A longer identity keeps even zero-count inputs above 75 bytes.
            assert!(
                hello_fields(&hello(b"a.example", b"service", &bad, &[0xf001])).is_none(),
                "versions {bad:?}"
            );
        }
        for bad in [
            vec![],
            vec![0, 0xf001],
            vec![0xf001, 0xf001],
            vec![0xf001, 1],
            vec![1],
            vec![1, 2, 3, 4, 5, 6, 7, 8, 0xf001],
        ] {
            assert!(
                hello_fields(&hello(b"a.example", b"service", &[1], &bad)).is_none(),
                "suites {bad:?}"
            );
        }
        assert_eq!(
            hello_fields(&hello(b"a", b"b", &[1, 256], &[1, 0xf001, 0xffff])),
            Some(("a", "b"))
        );
    }

    #[test]
    fn hello_dns_and_service_grammar() {
        for name in [
            b"".as_slice(),
            b"A.example",
            b"a..b",
            b".a",
            b"a.",
            b"-a",
            b"a-",
            b"a_b",
            b"127.0.0.1",
            b"::1",
            b"a\0b",
            "\u{e9}.example".as_bytes(),
        ] {
            assert!(
                hello_fields(&hello(name, b"service", &[1], &[0xf001])).is_none(),
                "name {name:?}"
            );
        }
        for name in [
            "a".repeat(64),
            [
                "a".repeat(63),
                "b".repeat(63),
                "c".repeat(63),
                "d".repeat(62),
            ]
            .join("."),
        ] {
            assert!(hello_fields(&hello(name.as_bytes(), b"s", &[1], &[0xf001])).is_none());
        }
        for service in [
            b"".as_slice(),
            b"Upper",
            b".a",
            b"_a",
            b"/a",
            b"-a",
            b"a b",
            b"a:b",
            b"a\0b",
            "\u{e9}".as_bytes(),
        ] {
            assert!(
                hello_fields(&hello(b"a.example", service, &[1], &[0xf001])).is_none(),
                "service {service:?}"
            );
        }
        assert!(hello_fields(&hello(b"a", &[b'x'; 65], &[1], &[0xf001])).is_none());
        assert_eq!(
            hello_fields(&hello(
                b"xn--bcher-kva.example",
                b"a.b_c/d-e",
                &[1],
                &[0xf001]
            )),
            Some(("xn--bcher-kva.example", "a.b_c/d-e"))
        );
    }

    #[test]
    fn hello_lengths_truncation_and_trailing_data() {
        let raw = fixture_frame("client_hello");
        let payload = &raw[40..];
        for end in 0..payload.len() {
            assert!(
                hello_fields(&payload[..end]).is_none(),
                "truncated to {end}"
            );
        }
        let mut trailing = payload.to_vec();
        trailing.push(0);
        assert!(hello_fields(&trailing).is_none());
        for index in [64, 67, 70, 71, 73] {
            let mut bad = hello(b"a", b"b", &[1], &[0xf001]);
            bad[index] = 0xff;
            assert!(hello_fields(&bad).is_none(), "length or count byte {index}");
        }
    }
}
