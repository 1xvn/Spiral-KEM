#![no_main]
mod record_checks;
mod record_model;
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    record_checks::record(data);
});
