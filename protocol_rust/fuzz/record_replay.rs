#![forbid(unsafe_code)]
mod record_checks;
mod record_model;
use serde_json::json;
use std::{
    env, fs,
    io::{self, Write},
    process,
};

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    if args.next().as_deref() != Some("record") {
        return Err("expected record and input files".into());
    }
    let paths: Vec<String> = args.collect();
    if paths.is_empty() {
        return Err("no replay inputs".into());
    }
    let mut output = io::BufWriter::new(io::stdout().lock());
    for path in paths {
        if fs::metadata(&path)?.len() > record_model::MAX_INPUT as u64 {
            return Err("replay input exceeds 258 bytes".into());
        }
        let data = fs::read(&path)?;
        if data.len() > record_model::MAX_INPUT {
            return Err("replay input grew during read".into());
        }
        let result = record_checks::record(&data);
        serde_json::to_writer(&mut output, &json!({"file":path,"result":result}))?;
        writeln!(output)?;
    }
    output.flush()?;
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("record replay: {error}");
        process::exit(1);
    }
}
