//! Parser-only entry point for the opt-in fuzzing harness.
#![forbid(unsafe_code)]

/// Parse a ClientHello payload using the production handshake parser.
#[inline(never)]
pub fn parse_client_hello(data: &[u8]) -> crate::Result<(&str, &str)> {
    crate::handshake::parse_hello(data)
}

/// Parse a frame using the production wire parser.
#[inline(never)]
pub fn parse_frame(data: &[u8]) -> crate::Result<(crate::wire::Header, &[u8])> {
    crate::wire::parse(data)
}

#[cfg(test)]
mod tests {
    use super::{parse_client_hello, parse_frame};

    fn client_hello_frame() -> Vec<u8> {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../protocol_v01/tests/fixtures/test_vectors_v0.1.json"
        ))
        .unwrap();
        hex::decode(vectors["frames"]["client_hello"].as_str().unwrap()).unwrap()
    }

    fn client_hello_payload() -> Vec<u8> {
        client_hello_frame()[crate::wire::HEADER..].to_vec()
    }

    #[test]
    fn parses_the_client_hello_frame_fixture() {
        let frame = client_hello_frame();
        let (header, payload) = parse_frame(&frame).unwrap();
        assert_eq!(header.kind, 1);
        assert_eq!(header.role, 0);
        assert_eq!(header.sid, [0; 16]);
        assert_eq!(header.sequence, 0);
        assert_eq!(header.length, frame.len() - crate::wire::HEADER);
        assert_eq!(payload, &frame[crate::wire::HEADER..]);
        assert!(parse_frame(&frame[..frame.len() - 1]).is_err());
    }

    #[test]
    fn parses_the_client_hello_fixture() {
        let payload = client_hello_payload();
        assert_eq!(
            parse_client_hello(&payload).unwrap(),
            ("spiral-lab.example", "spiral-research")
        );
    }

    #[test]
    fn rejects_truncated_and_trailing_payloads() {
        let payload = client_hello_payload();
        for length in 0..payload.len() {
            assert_eq!(
                parse_client_hello(&payload[..length]),
                Err(crate::Error::Input)
            );
        }
        let mut trailing = payload;
        trailing.push(0);
        assert_eq!(parse_client_hello(&trailing), Err(crate::Error::Input));
    }

    #[test]
    fn rejects_missing_required_offers_and_invalid_utf8() {
        let payload = client_hello_payload();
        for offset in [64, 67] {
            let mut empty_offer = payload.clone();
            empty_offer[offset] = 0;
            assert_eq!(parse_client_hello(&empty_offer), Err(crate::Error::Input));
        }
        let mut invalid_name = payload;
        invalid_name[72] = 0xff;
        assert_eq!(parse_client_hello(&invalid_name), Err(crate::Error::Input));
    }
}
