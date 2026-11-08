//! Test-only client requests from Valgrind 3.24 valgrind.h, amd64/arm64 Linux.
//! No native byte values are changed; secret marks affect Memcheck shadow only.

fn request(code: usize, address: usize, length: usize) -> usize {
    let arguments = [code, address, length, 0, 0, 0];
    let mut result = 0usize;
    // SAFETY: the live request array is read synchronously. Neither block is
    // marked nomem/pure: the request can read/write pointed-to shadow state.
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "rol rdi, 3", "rol rdi, 13", "rol rdi, 61", "rol rdi, 51",
            "xchg rbx, rbx",
            in("rax") arguments.as_ptr(), inout("rdx") result,
            lateout("rdi") _, options(nostack),
        );
    }
    // SAFETY: valgrind.h PLAT_arm64_linux uses X4 for the argument pointer and
    // X3 for default/result, with the four X12 rotations and X10 self-OR marker.
    // Rotations total 128 bits, restoring X12; OR leaves X10 unchanged.
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!(
            "ror x12, x12, #3", "ror x12, x12, #13",
            "ror x12, x12, #51", "ror x12, x12, #61",
            "orr x10, x10, x10",
            in("x4") arguments.as_ptr(), inout("x3") result,
            lateout("x12") _, options(nostack),
        );
    }
    result
}

pub(crate) fn require_valgrind() {
    assert!(request(0x1001, 0, 0) > 0, "run this ignored test under Valgrind Memcheck");
}

pub(crate) fn mark_secret(bytes: &mut [u8]) {
    request(0x4d43_0001, bytes.as_mut_ptr() as usize, bytes.len());
}

// Only existing wire outputs of derivation/sealing/signing use this operation.
// The receive trace never invokes it, including for authentication decisions.
pub(crate) fn mark_public(bytes: &mut [u8]) {
    request(0x4d43_0002, bytes.as_mut_ptr() as usize, bytes.len());
}
