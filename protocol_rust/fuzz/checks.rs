//! Independent decisions live in the uninstrumented driver crate.
use crate::oracles;
use spiral_protocol::{test_support, wire, Error};

#[allow(dead_code)]
pub fn frame(data: &[u8]) {
    let expected = oracles::frame_is_valid(data);
    match test_support::parse_frame(data) {
        Ok((header, payload)) => {
            assert!(expected, "reference-invalid frame accepted");
            assert_eq!(header.kind, data[6]);
            assert_eq!(header.role, data[7]);
            assert_eq!(header.sid.as_slice(), &data[12..28]);
            assert_eq!(
                header.sequence,
                u64::from_be_bytes(data[28..36].try_into().unwrap())
            );
            assert_eq!(
                header.length,
                u32::from_be_bytes(data[36..40].try_into().unwrap()) as usize
            );
            assert_eq!(payload, &data[40..]);
            assert_eq!(
                wire::frame(
                    header.kind,
                    header.role,
                    header.sid,
                    header.sequence,
                    payload
                )
                .unwrap(),
                data
            );
        }
        Err(Error::Input) => assert!(!expected, "reference-valid frame rejected"),
        Err(_) => panic!("frame parser returned an unexpected error kind"),
    }
}

#[allow(dead_code)]
pub fn hello(data: &[u8]) {
    let expected = oracles::hello_fields(data);
    match (expected, test_support::parse_client_hello(data)) {
        (Some((name, service)), Ok((actual_name, actual_service))) => {
            assert_eq!(actual_name, name);
            assert_eq!(actual_service, service);
        }
        (None, Err(Error::Input)) => {}
        _ => panic!("ClientHello parser disagrees with independent reference"),
    }
}
