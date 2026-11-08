#![no_std]
#[path="/workspace/spiral-arm-secret-flow-20261108/protocol_rust/src/valgrind_audit.rs"] mod audit;
#[unsafe(no_mangle)] pub unsafe extern "C" fn mark_probe(p: *mut u8) { audit::mark_secret(core::slice::from_raw_parts_mut(p,32)); }
