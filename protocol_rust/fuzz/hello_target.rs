#![no_main]
mod checks;
mod oracles;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    checks::hello(data);
});
