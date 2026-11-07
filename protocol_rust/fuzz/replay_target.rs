#![forbid(unsafe_code)]
mod checks;
mod oracles;

use serde_json::json;
use spiral_protocol::{test_support, Error};
use std::{
    env, fs,
    io::{self, Write},
    process,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("replay: {error}");
        process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let target = args.next().ok_or("expected frame|hello and input files")?;
    let limit = match target.as_str() {
        "frame" => 16500,
        "hello" => 512,
        _ => return Err("unknown replay target".into()),
    };
    let paths: Vec<String> = args.collect();
    if paths.is_empty() {
        return Err("no replay input files".into());
    }
    let mut output = io::BufWriter::new(io::stdout().lock());
    for path in paths {
        if fs::metadata(&path)?.len() > limit {
            return Err(format!("input exceeds {limit} bytes: {path}").into());
        }
        let data = fs::read(&path)?;
        if data.len() as u64 > limit {
            return Err("input grew during read".into());
        }
        let result = if target == "frame" {
            checks::frame(&data);
            match test_support::parse_frame(&data) {
                Ok((header, payload)) => json!({"accepted":true,"kind":header.kind,
                    "role":header.role,"sid":hex::encode(header.sid),"sequence":header.sequence,
                    "length":header.length,"payload":hex::encode(payload)}),
                Err(Error::Input) => json!({"accepted":false}),
                Err(_) => return Err("unexpected frame error kind".into()),
            }
        } else {
            checks::hello(&data);
            match test_support::parse_client_hello(&data) {
                Ok((name, service)) => json!({"accepted":true,"name":name,"service":service}),
                Err(Error::Input) => json!({"accepted":false}),
                Err(_) => return Err("unexpected hello error kind".into()),
            }
        };
        serde_json::to_writer(&mut output, &json!({"file":path,"result":result}))?;
        writeln!(output)?;
    }
    output.flush()?;
    Ok(())
}
