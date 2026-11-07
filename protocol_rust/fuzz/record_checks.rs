//! The input grammar and all model comparisons live in this uninstrumented crate.
use crate::record_model::{self as model, Fault, Model};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use spiral_protocol::{
    record_test_support::{RecordPair, Snapshot},
    Error,
};

fn fault(error: Error) -> Fault {
    match error {
        Error::Input => Fault::Input,
        Error::Closed => Fault::Closed,
        Error::Authentication => Fault::Authentication,
        Error::Limit(2) => Fault::Limit2,
        other => panic!("unexpected production record error: {other:?}"),
    }
}
fn snapshot(state: Snapshot) -> Value {
    json!({"sequence":state.sequence,"bytes":state.bytes,
        "closed":state.closed,"key_live":state.key_live})
}
fn states(pair: &RecordPair, model: &Model) -> (Value, Value) {
    let (tx, rx) = pair.snapshots();
    let tx = snapshot(tx);
    let rx = snapshot(rx);
    assert_eq!(
        tx,
        model.tx.json(),
        "Tx state disagrees with independent model"
    );
    assert_eq!(
        rx,
        model.rx.json(),
        "Rx state disagrees with independent model"
    );
    (tx, rx)
}
fn success(bytes: &[u8]) -> Value {
    json!({"ok":true,"length":bytes.len(),"sha256":hex::encode(Sha256::digest(bytes))})
}
fn rejected(error: Fault) -> Value {
    json!({"ok":false,"error":error.label()})
}
fn stored(frames: &[Vec<u8>], index: u8) -> Vec<u8> {
    if frames.is_empty() {
        Vec::new()
    } else {
        frames[index as usize % frames.len()].clone()
    }
}

pub fn record(data: &[u8]) -> Value {
    let data = &data[..data.len().min(model::MAX_INPUT)];
    let scenario = data.first().copied().unwrap_or(0) % 7;
    let role = data.get(1).copied().unwrap_or(0) & 1;
    let mut pair = RecordPair::new(scenario, role).unwrap();
    let mut reference = Model::new(scenario, role);
    let (tx, rx) = states(&pair, &reference);
    let initial = json!({"tx":tx,"rx":rx});
    let mut frames = Vec::new();
    let mut steps = Vec::new();
    let mut accepted = true;
    for command in data.get(2..).unwrap_or(&[]).chunks_exact(4) {
        let (op, a, b, c) = (command[0] % 6, command[1], command[2], command[3]);
        let answer = if op <= 1 {
            let (actual, expected) = if op == 0 {
                let plaintext = model::pattern(model::LENGTHS[(a % 7) as usize], b, c);
                (
                    pair.data(&plaintext).map_err(fault),
                    reference.data(&plaintext),
                )
            } else {
                (pair.close(a).map_err(fault), reference.close(a))
            };
            assert_eq!(
                actual, expected,
                "emitted wire/error disagrees with independent AEAD model"
            );
            match actual {
                Ok(wire) => {
                    let value = success(&wire);
                    frames.push(wire);
                    value
                }
                Err(error) => rejected(error),
            }
        } else {
            let wire = match op {
                2 => stored(&frames, a),
                3 => model::mutate(stored(&frames, a), b, c),
                4 => model::craft(&reference.rx, role, a, b, c),
                5 => [a, b, c].repeat((c % 17) as usize),
                _ => unreachable!(),
            };
            let actual = pair.decode(&wire).map_err(fault);
            let expected = reference.receive(&wire);
            assert_eq!(
                actual, expected,
                "decoded plaintext/error disagrees with independent AEAD model"
            );
            match actual {
                Ok((kind, plaintext)) => {
                    let mut result = success(&plaintext);
                    result["kind"] = json!(kind);
                    result
                }
                Err(error) => rejected(error),
            }
        };
        accepted &= answer["ok"].as_bool().unwrap();
        let (tx, rx) = states(&pair, &reference);
        let operation = ["data", "close", "deliver", "mutate", "craft", "raw"][op as usize];
        steps.push(json!({"op":operation,
            "result":answer,"tx":tx,"rx":rx}));
    }
    json!({"accepted":accepted,"scenario":scenario,"role":role,"initial":initial,"steps":steps})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn production_success_and_post_close_failures() {
        let trace = record(&[
            0, 0, 0, 1, 42, 1, 2, 0, 0, 0, 1, 0, 0, 0, 2, 1, 0, 0, 0, 1, 0, 0, 2, 0, 0, 0,
        ]);
        assert_eq!(trace["steps"][1]["result"]["kind"], 16);
        assert_eq!(trace["steps"][3]["result"]["kind"], 17);
        assert_eq!(trace["steps"][4]["result"]["error"], "Closed");
        assert_eq!(trace["steps"][5]["result"]["error"], "Closed");
    }
    #[test]
    fn all_constructor_boundaries_and_roles_match() {
        for scenario in 0..7 {
            for role in 0..2 {
                record(&[
                    scenario, role, 0, 1, 12, 1, 2, 0, 0, 0, 1, 0, 0, 0, 2, 1, 0, 0,
                ]);
            }
        }
    }
    #[test]
    fn input_cap_and_trailing_partial_command_are_defined() {
        assert_eq!(record(&[0, 0, 255]), record(&[0, 0]));
        let long = vec![0; 300];
        assert_eq!(record(&long), record(&long[..258]));
        assert_eq!(record(&long)["steps"].as_array().unwrap().len(), 64);
    }
}
