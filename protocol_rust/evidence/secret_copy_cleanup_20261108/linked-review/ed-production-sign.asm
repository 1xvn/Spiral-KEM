
/workspace/secret-copy-standalone-local/build/audit/deps/spiral_protocol-4ed2cea9ed487504:     file format elf64-x86-64


Disassembly of section .text:

00000000001314a0 <<spiral_protocol::identity::ServerIdentity>::sign>:
<spiral_protocol::identity::ServerIdentity>::sign:
/tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:73
  1314a0:	55                   	push   %rbp
  1314a1:	41 57                	push   %r15
  1314a3:	41 56                	push   %r14
  1314a5:	41 55                	push   %r13
  1314a7:	41 54                	push   %r12
  1314a9:	53                   	push   %rbx
  1314aa:	48 83 ec 68          	sub    $0x68,%rsp
/tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74
  1314ae:	48 8d 5e 20          	lea    0x20(%rsi),%rbx
core::sync::atomic::atomic_compare_exchange::<u32>:
/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/sync/atomic.rs:4083
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/sync/atomic.rs:3119 (_RNvMsQ_NtNtCskADBYZwJmSU_4core4sync6atomicINtB5_6AtomicmE16compare_exchange)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:32 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex4lock)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:492 (_RNvMs5_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_5MutexINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE4lockCs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1314b2:	41 b8 01 00 00 00    	mov    $0x1,%r8d
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/sync/atomic.rs:3119 (_RNvMsQ_NtNtCskADBYZwJmSU_4core4sync6atomicINtB5_6AtomicmE16compare_exchange)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:32 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex4lock)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:492 (_RNvMs5_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_5MutexINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE4lockCs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1314b8:	31 c0                	xor    %eax,%eax
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/sync/atomic.rs:3119 (_RNvMsQ_NtNtCskADBYZwJmSU_4core4sync6atomicINtB5_6AtomicmE16compare_exchange)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:32 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex4lock)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:492 (_RNvMs5_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_5MutexINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE4lockCs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1314ba:	f0 44 0f b1 46 20    	lock cmpxchg %r8d,0x20(%rsi)
<std::sys::sync::mutex::futex::Mutex>::lock:
/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:32
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:492 (_RNvMs5_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_5MutexINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE4lockCs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1314c0:	75 56                	jne    131518 <<spiral_protocol::identity::ServerIdentity>::sign+0x78>
core::sync::atomic::atomic_load::<usize>:
/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/sync/atomic.rs:3994
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/sync/atomic.rs:2916 (_RNvMs16_NtNtCskADBYZwJmSU_4core4sync6atomicINtB6_6AtomicjE4load)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/panicking.rs:465 (_RNvNtNtCs8ZKwes1zzDd_3std9panicking11panic_count13count_is_zero)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/panicking.rs:606 (_RNvNtCs8ZKwes1zzDd_3std9panicking9panicking)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/thread/functions.rs:221 (_RNvNtNtCs8ZKwes1zzDd_3std6thread9functions9panicking)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison.rs:118 (_RNvMNtNtCs8ZKwes1zzDd_3std4sync6poisonNtB2_4Flag5guard)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:720 (_RNvMs9_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE3newCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:493 (_RNvMs5_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_5MutexINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE4lockCs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1314c2:	4c 8b 35 77 ff 11 00 	mov    0x11ff77(%rip),%r14        # 251440 <_DYNAMIC+0xbb8>
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/sync/atomic.rs:2916 (_RNvMs16_NtNtCskADBYZwJmSU_4core4sync6atomicINtB6_6AtomicjE4load)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/panicking.rs:465 (_RNvNtNtCs8ZKwes1zzDd_3std9panicking11panic_count13count_is_zero)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/panicking.rs:606 (_RNvNtCs8ZKwes1zzDd_3std9panicking9panicking)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/thread/functions.rs:221 (_RNvNtNtCs8ZKwes1zzDd_3std6thread9functions9panicking)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison.rs:118 (_RNvMNtNtCs8ZKwes1zzDd_3std4sync6poisonNtB2_4Flag5guard)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:720 (_RNvMs9_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE3newCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:493 (_RNvMs5_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_5MutexINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE4lockCs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1314c9:	49 8b 06             	mov    (%r14),%rax
std::panicking::panic_count::count_is_zero:
/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/panicking.rs:465
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/panicking.rs:606 (_RNvNtCs8ZKwes1zzDd_3std9panicking9panicking)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/thread/functions.rs:221 (_RNvNtNtCs8ZKwes1zzDd_3std6thread9functions9panicking)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison.rs:118 (_RNvMNtNtCs8ZKwes1zzDd_3std4sync6poisonNtB2_4Flag5guard)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:720 (_RNvMs9_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE3newCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:493 (_RNvMs5_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_5MutexINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE4lockCs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1314cc:	48 d1 e0             	shl    $1,%rax
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/panicking.rs:606 (_RNvNtCs8ZKwes1zzDd_3std9panicking9panicking)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/thread/functions.rs:221 (_RNvNtNtCs8ZKwes1zzDd_3std6thread9functions9panicking)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison.rs:118 (_RNvMNtNtCs8ZKwes1zzDd_3std4sync6poisonNtB2_4Flag5guard)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:720 (_RNvMs9_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE3newCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:493 (_RNvMs5_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_5MutexINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE4lockCs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1314cf:	48 85 c0             	test   %rax,%rax
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/panicking.rs:606 (_RNvNtCs8ZKwes1zzDd_3std9panicking9panicking)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/thread/functions.rs:221 (_RNvNtNtCs8ZKwes1zzDd_3std6thread9functions9panicking)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison.rs:118 (_RNvMNtNtCs8ZKwes1zzDd_3std4sync6poisonNtB2_4Flag5guard)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:720 (_RNvMs9_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE3newCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:493 (_RNvMs5_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_5MutexINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE4lockCs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1314d2:	75 67                	jne    13153b <<spiral_protocol::identity::ServerIdentity>::sign+0x9b>
<std::sync::poison::Flag>::guard:
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:720 (_RNvMs9_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE3newCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:493 (_RNvMs5_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_5MutexINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE4lockCs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1314d4:	31 ed                	xor    %ebp,%ebp
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:720 (_RNvMs9_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE3newCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:493 (_RNvMs5_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_5MutexINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE4lockCs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1314d6:	49 bf ff ff ff ff ff 	movabs $0x7fffffffffffffff,%r15
  1314dd:	ff ff 7f 
core::sync::atomic::atomic_load::<u8>:
/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/sync/atomic.rs:3994
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/sync/atomic.rs:762 (_RNvMs2_NtNtCskADBYZwJmSU_4core4sync6atomicINtB5_6AtomicbE4load)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison.rs:138 (_RNvMNtNtCs8ZKwes1zzDd_3std4sync6poisonNtB2_4Flag3get)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison.rs:120 (_RNvMNtNtCs8ZKwes1zzDd_3std4sync6poisonNtB2_4Flag5guard)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:720 (_RNvMs9_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE3newCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:493 (_RNvMs5_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_5MutexINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE4lockCs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1314e0:	0f b6 46 24          	movzbl 0x24(%rsi),%eax
<core::sync::atomic::Atomic<bool>>::load:
/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/sync/atomic.rs:762
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison.rs:138 (_RNvMNtNtCs8ZKwes1zzDd_3std4sync6poisonNtB2_4Flag3get)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison.rs:120 (_RNvMNtNtCs8ZKwes1zzDd_3std4sync6poisonNtB2_4Flag5guard)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:720 (_RNvMs9_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE3newCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:493 (_RNvMs5_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_5MutexINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE4lockCs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1314e4:	84 c0                	test   %al,%al
<core::result::Result<std::sync::poison::mutex::MutexGuard<core::option::Option<ed25519_dalek::signing::SigningKey>>, std::sync::poison::PoisonError<std::sync::poison::mutex::MutexGuard<core::option::Option<ed25519_dalek::signing::SigningKey>>>>>::map_err::<spiral_protocol::error::Error, <spiral_protocol::identity::ServerIdentity>::sign::{closure#0}>:
/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/result.rs:965
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1314e6:	0f 84 89 00 00 00    	je     131575 <<spiral_protocol::identity::ServerIdentity>::sign+0xd5>
<std::sync::poison::Flag>::done:
/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison.rs:126
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:745 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtCs8ZKwes1zzDd_3std4sync6poison11PoisonErrorINtNtBE_5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNCNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB4_14ServerIdentity4sign0B6_)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/result.rs:967 (_RINvMNtCskADBYZwJmSU_4core6resultINtB3_6ResultINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB5_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEINtBN_11PoisonErrorBI_EE7map_errNtNtCs9LFm1b3AnVj_15spiral_protocol5error5ErrorNCNvMNtB3s_8identityNtB4e_14ServerIdentity4sign0EB3s_)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1314ec:	40 84 ed             	test   %bpl,%bpl
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:745 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtCs8ZKwes1zzDd_3std4sync6poison11PoisonErrorINtNtBE_5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNCNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB4_14ServerIdentity4sign0B6_)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/result.rs:967 (_RINvMNtCskADBYZwJmSU_4core6resultINtB3_6ResultINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB5_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEINtBN_11PoisonErrorBI_EE7map_errNtNtCs9LFm1b3AnVj_15spiral_protocol5error5ErrorNCNvMNtB3s_8identityNtB4e_14ServerIdentity4sign0EB3s_)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1314ef:	75 0c                	jne    1314fd <<spiral_protocol::identity::ServerIdentity>::sign+0x5d>
core::sync::atomic::atomic_load::<usize>:
/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/sync/atomic.rs:3994
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/sync/atomic.rs:2916 (_RNvMs16_NtNtCskADBYZwJmSU_4core4sync6atomicINtB6_6AtomicjE4load)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/panicking.rs:465 (_RNvNtNtCs8ZKwes1zzDd_3std9panicking11panic_count13count_is_zero)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/panicking.rs:606 (_RNvNtCs8ZKwes1zzDd_3std9panicking9panicking)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/thread/functions.rs:221 (_RNvNtNtCs8ZKwes1zzDd_3std6thread9functions9panicking)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison.rs:126 (_RNvMNtNtCs8ZKwes1zzDd_3std4sync6poisonNtB2_4Flag4done)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:745 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtCs8ZKwes1zzDd_3std4sync6poison11PoisonErrorINtNtBE_5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNCNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB4_14ServerIdentity4sign0B6_)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/result.rs:967 (_RINvMNtCskADBYZwJmSU_4core6resultINtB3_6ResultINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB5_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEINtBN_11PoisonErrorBI_EE7map_errNtNtCs9LFm1b3AnVj_15spiral_protocol5error5ErrorNCNvMNtB3s_8identityNtB4e_14ServerIdentity4sign0EB3s_)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1314f1:	49 8b 06             	mov    (%r14),%rax
std::panicking::panic_count::count_is_zero:
/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/panicking.rs:465
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/panicking.rs:606 (_RNvNtCs8ZKwes1zzDd_3std9panicking9panicking)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/thread/functions.rs:221 (_RNvNtNtCs8ZKwes1zzDd_3std6thread9functions9panicking)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison.rs:126 (_RNvMNtNtCs8ZKwes1zzDd_3std4sync6poisonNtB2_4Flag4done)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:745 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtCs8ZKwes1zzDd_3std4sync6poison11PoisonErrorINtNtBE_5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNCNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB4_14ServerIdentity4sign0B6_)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/result.rs:967 (_RINvMNtCskADBYZwJmSU_4core6resultINtB3_6ResultINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB5_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEINtBN_11PoisonErrorBI_EE7map_errNtNtCs9LFm1b3AnVj_15spiral_protocol5error5ErrorNCNvMNtB3s_8identityNtB4e_14ServerIdentity4sign0EB3s_)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1314f4:	4c 85 f8             	test   %r15,%rax
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/panicking.rs:606 (_RNvNtCs8ZKwes1zzDd_3std9panicking9panicking)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/thread/functions.rs:221 (_RNvNtNtCs8ZKwes1zzDd_3std6thread9functions9panicking)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison.rs:126 (_RNvMNtNtCs8ZKwes1zzDd_3std4sync6poisonNtB2_4Flag4done)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:745 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtCs8ZKwes1zzDd_3std4sync6poison11PoisonErrorINtNtBE_5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNCNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB4_14ServerIdentity4sign0B6_)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/result.rs:967 (_RINvMNtCskADBYZwJmSU_4core6resultINtB3_6ResultINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB5_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEINtBN_11PoisonErrorBI_EE7map_errNtNtCs9LFm1b3AnVj_15spiral_protocol5error5ErrorNCNvMNtB3s_8identityNtB4e_14ServerIdentity4sign0EB3s_)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1314f7:	0f 85 89 01 00 00    	jne    131686 <<spiral_protocol::identity::ServerIdentity>::sign+0x1e6>
core::sync::atomic::atomic_swap::<u32>:
/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/sync/atomic.rs:4013
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/sync/atomic.rs:2977 (_RNvMsQ_NtNtCskADBYZwJmSU_4core4sync6atomicINtB5_6AtomicmE4swap)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:90 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex6unlock)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:746 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtCs8ZKwes1zzDd_3std4sync6poison11PoisonErrorINtNtBE_5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNCNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB4_14ServerIdentity4sign0B6_)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/result.rs:967 (_RINvMNtCskADBYZwJmSU_4core6resultINtB3_6ResultINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB5_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEINtBN_11PoisonErrorBI_EE7map_errNtNtCs9LFm1b3AnVj_15spiral_protocol5error5ErrorNCNvMNtB3s_8identityNtB4e_14ServerIdentity4sign0EB3s_)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1314fd:	31 c0                	xor    %eax,%eax
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/sync/atomic.rs:2977 (_RNvMsQ_NtNtCskADBYZwJmSU_4core4sync6atomicINtB5_6AtomicmE4swap)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:90 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex6unlock)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:746 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtCs8ZKwes1zzDd_3std4sync6poison11PoisonErrorINtNtBE_5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNCNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB4_14ServerIdentity4sign0B6_)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/result.rs:967 (_RINvMNtCskADBYZwJmSU_4core6resultINtB3_6ResultINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB5_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEINtBN_11PoisonErrorBI_EE7map_errNtNtCs9LFm1b3AnVj_15spiral_protocol5error5ErrorNCNvMNtB3s_8identityNtB4e_14ServerIdentity4sign0EB3s_)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1314ff:	87 03                	xchg   %eax,(%rbx)
<std::sys::sync::mutex::futex::Mutex>::unlock:
/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:90
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:746 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtCs8ZKwes1zzDd_3std4sync6poison11PoisonErrorINtNtBE_5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNCNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB4_14ServerIdentity4sign0B6_)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/result.rs:967 (_RINvMNtCskADBYZwJmSU_4core6resultINtB3_6ResultINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB5_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEINtBN_11PoisonErrorBI_EE7map_errNtNtCs9LFm1b3AnVj_15spiral_protocol5error5ErrorNCNvMNtB3s_8identityNtB4e_14ServerIdentity4sign0EB3s_)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131501:	83 f8 02             	cmp    $0x2,%eax
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:746 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtCs8ZKwes1zzDd_3std4sync6poison11PoisonErrorINtNtBE_5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNCNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB4_14ServerIdentity4sign0B6_)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/result.rs:967 (_RINvMNtCskADBYZwJmSU_4core6resultINtB3_6ResultINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB5_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEINtBN_11PoisonErrorBI_EE7map_errNtNtCs9LFm1b3AnVj_15spiral_protocol5error5ErrorNCNvMNtB3s_8identityNtB4e_14ServerIdentity4sign0EB3s_)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131504:	0f 84 57 01 00 00    	je     131661 <<spiral_protocol::identity::ServerIdentity>::sign+0x1c1>
<core::result::Result<ed25519::Signature, spiral_protocol::error::Error> as core::ops::try_trait::FromResidual<core::result::Result<core::convert::Infallible, spiral_protocol::error::Error>>>::from_residual:
/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/result.rs:2193
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  13150a:	c6 47 02 00          	movb   $0x0,0x2(%rdi)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  13150e:	66 c7 07 01 09       	movw   $0x901,(%rdi)
<spiral_protocol::identity::ServerIdentity>::sign:
  131513:	e9 3a 01 00 00       	jmp    131652 <<spiral_protocol::identity::ServerIdentity>::sign+0x1b2>
  131518:	49 89 fe             	mov    %rdi,%r14
<std::sys::sync::mutex::futex::Mutex>::lock:
/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:33
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:492 (_RNvMs5_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_5MutexINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE4lockCs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  13151b:	48 89 df             	mov    %rbx,%rdi
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:492 (_RNvMs5_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_5MutexINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE4lockCs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  13151e:	49 89 f7             	mov    %rsi,%r15
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:492 (_RNvMs5_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_5MutexINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE4lockCs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131521:	49 89 cd             	mov    %rcx,%r13
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:492 (_RNvMs5_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_5MutexINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE4lockCs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131524:	49 89 d4             	mov    %rdx,%r12
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:492 (_RNvMs5_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_5MutexINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE4lockCs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131527:	ff 15 1b ff 11 00    	call   *0x11ff1b(%rip)        # 251448 <_DYNAMIC+0xbc0>
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:492 (_RNvMs5_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_5MutexINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE4lockCs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  13152d:	4c 89 e2             	mov    %r12,%rdx
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:492 (_RNvMs5_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_5MutexINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE4lockCs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131530:	4c 89 e9             	mov    %r13,%rcx
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:492 (_RNvMs5_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_5MutexINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE4lockCs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131533:	4c 89 f7             	mov    %r14,%rdi
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:492 (_RNvMs5_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_5MutexINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE4lockCs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131536:	4c 89 fe             	mov    %r15,%rsi
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:492 (_RNvMs5_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_5MutexINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE4lockCs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131539:	eb 87                	jmp    1314c2 <<spiral_protocol::identity::ServerIdentity>::sign+0x22>
<std::sync::poison::mutex::Mutex<core::option::Option<ed25519_dalek::signing::SigningKey>>>::lock:
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  13153b:	49 89 f7             	mov    %rsi,%r15
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  13153e:	49 89 fd             	mov    %rdi,%r13
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131541:	49 89 cc             	mov    %rcx,%r12
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131544:	48 89 d5             	mov    %rdx,%rbp
std::panicking::panic_count::count_is_zero:
/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/panicking.rs:477
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/panicking.rs:606 (_RNvNtCs8ZKwes1zzDd_3std9panicking9panicking)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/thread/functions.rs:221 (_RNvNtNtCs8ZKwes1zzDd_3std6thread9functions9panicking)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison.rs:118 (_RNvMNtNtCs8ZKwes1zzDd_3std4sync6poisonNtB2_4Flag5guard)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:720 (_RNvMs9_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE3newCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:493 (_RNvMs5_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_5MutexINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE4lockCs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131547:	ff 15 03 ff 11 00    	call   *0x11ff03(%rip)        # 251450 <_DYNAMIC+0xbc8>
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/panicking.rs:606 (_RNvNtCs8ZKwes1zzDd_3std9panicking9panicking)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/thread/functions.rs:221 (_RNvNtNtCs8ZKwes1zzDd_3std6thread9functions9panicking)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison.rs:118 (_RNvMNtNtCs8ZKwes1zzDd_3std4sync6poisonNtB2_4Flag5guard)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:720 (_RNvMs9_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE3newCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:493 (_RNvMs5_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_5MutexINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE4lockCs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  13154d:	48 89 ea             	mov    %rbp,%rdx
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/panicking.rs:606 (_RNvNtCs8ZKwes1zzDd_3std9panicking9panicking)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/thread/functions.rs:221 (_RNvNtNtCs8ZKwes1zzDd_3std6thread9functions9panicking)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison.rs:118 (_RNvMNtNtCs8ZKwes1zzDd_3std4sync6poisonNtB2_4Flag5guard)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:720 (_RNvMs9_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE3newCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:493 (_RNvMs5_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_5MutexINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE4lockCs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131550:	4c 89 e1             	mov    %r12,%rcx
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/panicking.rs:606 (_RNvNtCs8ZKwes1zzDd_3std9panicking9panicking)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/thread/functions.rs:221 (_RNvNtNtCs8ZKwes1zzDd_3std6thread9functions9panicking)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison.rs:118 (_RNvMNtNtCs8ZKwes1zzDd_3std4sync6poisonNtB2_4Flag5guard)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:720 (_RNvMs9_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE3newCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:493 (_RNvMs5_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_5MutexINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE4lockCs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131553:	4c 89 ef             	mov    %r13,%rdi
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/panicking.rs:606 (_RNvNtCs8ZKwes1zzDd_3std9panicking9panicking)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/thread/functions.rs:221 (_RNvNtNtCs8ZKwes1zzDd_3std6thread9functions9panicking)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison.rs:118 (_RNvMNtNtCs8ZKwes1zzDd_3std4sync6poisonNtB2_4Flag5guard)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:720 (_RNvMs9_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE3newCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:493 (_RNvMs5_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_5MutexINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE4lockCs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131556:	4c 89 fe             	mov    %r15,%rsi
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/panicking.rs:606 (_RNvNtCs8ZKwes1zzDd_3std9panicking9panicking)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/thread/functions.rs:221 (_RNvNtNtCs8ZKwes1zzDd_3std6thread9functions9panicking)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison.rs:118 (_RNvMNtNtCs8ZKwes1zzDd_3std4sync6poisonNtB2_4Flag5guard)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:720 (_RNvMs9_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE3newCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:493 (_RNvMs5_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_5MutexINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE4lockCs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131559:	89 c5                	mov    %eax,%ebp
std::panicking::panicking:
/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/panicking.rs:606
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/thread/functions.rs:221 (_RNvNtNtCs8ZKwes1zzDd_3std6thread9functions9panicking)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison.rs:118 (_RNvMNtNtCs8ZKwes1zzDd_3std4sync6poisonNtB2_4Flag5guard)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:720 (_RNvMs9_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE3newCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:493 (_RNvMs5_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_5MutexINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE4lockCs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  13155b:	40 80 f5 01          	xor    $0x1,%bpl
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/thread/functions.rs:221 (_RNvNtNtCs8ZKwes1zzDd_3std6thread9functions9panicking)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison.rs:118 (_RNvMNtNtCs8ZKwes1zzDd_3std4sync6poisonNtB2_4Flag5guard)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:720 (_RNvMs9_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE3newCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:493 (_RNvMs5_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_5MutexINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE4lockCs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  13155f:	49 bf ff ff ff ff ff 	movabs $0x7fffffffffffffff,%r15
  131566:	ff ff 7f 
core::sync::atomic::atomic_load::<u8>:
/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/sync/atomic.rs:3994
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/sync/atomic.rs:762 (_RNvMs2_NtNtCskADBYZwJmSU_4core4sync6atomicINtB5_6AtomicbE4load)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison.rs:138 (_RNvMNtNtCs8ZKwes1zzDd_3std4sync6poisonNtB2_4Flag3get)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison.rs:120 (_RNvMNtNtCs8ZKwes1zzDd_3std4sync6poisonNtB2_4Flag5guard)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:720 (_RNvMs9_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE3newCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:493 (_RNvMs5_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_5MutexINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE4lockCs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131569:	0f b6 46 24          	movzbl 0x24(%rsi),%eax
<core::sync::atomic::Atomic<bool>>::load:
/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/sync/atomic.rs:762
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison.rs:138 (_RNvMNtNtCs8ZKwes1zzDd_3std4sync6poisonNtB2_4Flag3get)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison.rs:120 (_RNvMNtNtCs8ZKwes1zzDd_3std4sync6poisonNtB2_4Flag5guard)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:720 (_RNvMs9_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE3newCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:493 (_RNvMs5_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_5MutexINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEE4lockCs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  13156d:	84 c0                	test   %al,%al
<core::result::Result<std::sync::poison::mutex::MutexGuard<core::option::Option<ed25519_dalek::signing::SigningKey>>, std::sync::poison::PoisonError<std::sync::poison::mutex::MutexGuard<core::option::Option<ed25519_dalek::signing::SigningKey>>>>>::map_err::<spiral_protocol::error::Error, <spiral_protocol::identity::ServerIdentity>::sign::{closure#0}>:
/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/result.rs:965
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  13156f:	0f 85 77 ff ff ff    	jne    1314ec <<spiral_protocol::identity::ServerIdentity>::sign+0x4c>
<spiral_protocol::identity::ServerIdentity>::sign:
/tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74
  131575:	48 89 1c 24          	mov    %rbx,(%rsp)
  131579:	40 88 6c 24 08       	mov    %bpl,0x8(%rsp)
<core::option::Option<ed25519_dalek::signing::SigningKey>>::as_ref:
/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/option.rs:743
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:76 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  13157e:	83 7e 28 01          	cmpl   $0x1,0x28(%rsi)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:76 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131582:	75 45                	jne    1315c9 <<spiral_protocol::identity::ServerIdentity>::sign+0x129>
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:76 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131584:	49 89 fd             	mov    %rdi,%r13
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:76 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131587:	49 89 f4             	mov    %rsi,%r12
/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/option.rs:744
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:76 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  13158a:	48 83 c6 30          	add    $0x30,%rsi
<ed25519_dalek::signing::SigningKey as signature::signer::Signer<ed25519::Signature>>::try_sign:
/tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/third_party/rustcrypto/ed25519-dalek/src/signing.rs:602
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:78 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  13158e:	48 89 54 24 10       	mov    %rdx,0x10(%rsp)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:78 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131593:	48 89 4c 24 18       	mov    %rcx,0x18(%rsp)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:78 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131598:	48 8d 7c 24 27       	lea    0x27(%rsp),%rdi
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:78 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  13159d:	48 8d 54 24 10       	lea    0x10(%rsp),%rdx
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:78 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1315a2:	b9 01 00 00 00       	mov    $0x1,%ecx
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:78 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1315a7:	ff 15 a3 f9 11 00    	call   *0x11f9a3(%rip)        # 250f50 <_DYNAMIC+0x6c8>
<core::result::Result<ed25519::Signature, signature::error::Error>>::map_err::<spiral_protocol::error::Error, <spiral_protocol::identity::ServerIdentity>::sign::{closure#1}>:
/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/result.rs:965
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:79 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1315ad:	80 7c 24 27 01       	cmpb   $0x1,0x27(%rsp)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:79 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1315b2:	4c 89 e8             	mov    %r13,%rax
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:79 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1315b5:	75 59                	jne    131610 <<spiral_protocol::identity::ServerIdentity>::sign+0x170>
/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/result.rs:967
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:79 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1315b7:	c6 40 01 02          	movb   $0x2,0x1(%rax)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:79 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1315bb:	b1 01                	mov    $0x1,%cl
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:79 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1315bd:	88 08                	mov    %cl,(%rax)
<std::sync::poison::Flag>::done:
/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison.rs:126
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:745 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1315bf:	40 84 ed             	test   %bpl,%bpl
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:745 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1315c2:	74 79                	je     13163d <<spiral_protocol::identity::ServerIdentity>::sign+0x19d>
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:745 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1315c4:	e9 80 00 00 00       	jmp    131649 <<spiral_protocol::identity::ServerIdentity>::sign+0x1a9>
<core::result::Result<ed25519::Signature, spiral_protocol::error::Error> as core::ops::try_trait::FromResidual<core::result::Result<core::convert::Infallible, spiral_protocol::error::Error>>>::from_residual:
/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/result.rs:2193
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:75 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1315c9:	66 c7 07 01 06       	movw   $0x601,(%rdi)
<std::sync::poison::Flag>::done:
/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison.rs:126
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:745 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1315ce:	40 84 ed             	test   %bpl,%bpl
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:745 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1315d1:	75 0c                	jne    1315df <<spiral_protocol::identity::ServerIdentity>::sign+0x13f>
core::sync::atomic::atomic_load::<usize>:
/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/sync/atomic.rs:3994
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/sync/atomic.rs:2916 (_RNvMs16_NtNtCskADBYZwJmSU_4core4sync6atomicINtB6_6AtomicjE4load)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/panicking.rs:465 (_RNvNtNtCs8ZKwes1zzDd_3std9panicking11panic_count13count_is_zero)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/panicking.rs:606 (_RNvNtCs8ZKwes1zzDd_3std9panicking9panicking)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/thread/functions.rs:221 (_RNvNtNtCs8ZKwes1zzDd_3std6thread9functions9panicking)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison.rs:126 (_RNvMNtNtCs8ZKwes1zzDd_3std4sync6poisonNtB2_4Flag4done)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:745 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1315d3:	49 8b 06             	mov    (%r14),%rax
std::panicking::panic_count::count_is_zero:
/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/panicking.rs:465
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/panicking.rs:606 (_RNvNtCs8ZKwes1zzDd_3std9panicking9panicking)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/thread/functions.rs:221 (_RNvNtNtCs8ZKwes1zzDd_3std6thread9functions9panicking)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison.rs:126 (_RNvMNtNtCs8ZKwes1zzDd_3std4sync6poisonNtB2_4Flag4done)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:745 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1315d6:	4c 85 f8             	test   %r15,%rax
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/panicking.rs:606 (_RNvNtCs8ZKwes1zzDd_3std9panicking9panicking)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/thread/functions.rs:221 (_RNvNtNtCs8ZKwes1zzDd_3std6thread9functions9panicking)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison.rs:126 (_RNvMNtNtCs8ZKwes1zzDd_3std4sync6poisonNtB2_4Flag4done)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:745 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1315d9:	0f 85 e4 00 00 00    	jne    1316c3 <<spiral_protocol::identity::ServerIdentity>::sign+0x223>
core::sync::atomic::atomic_swap::<u32>:
/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/sync/atomic.rs:4013
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/sync/atomic.rs:2977 (_RNvMsQ_NtNtCskADBYZwJmSU_4core4sync6atomicINtB5_6AtomicmE4swap)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:90 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex6unlock)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:746 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1315df:	31 c0                	xor    %eax,%eax
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/sync/atomic.rs:2977 (_RNvMsQ_NtNtCskADBYZwJmSU_4core4sync6atomicINtB5_6AtomicmE4swap)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:90 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex6unlock)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:746 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1315e1:	87 03                	xchg   %eax,(%rbx)
<std::sys::sync::mutex::futex::Mutex>::unlock:
/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:90
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:746 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1315e3:	83 f8 02             	cmp    $0x2,%eax
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:746 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1315e6:	75 6a                	jne    131652 <<spiral_protocol::identity::ServerIdentity>::sign+0x1b2>
std::sys::sync::futex::unix::futex_wake:
/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/futex/unix.rs:97
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:101 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex4wake)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:95 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex6unlock)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:746 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1315e8:	bf ca 00 00 00       	mov    $0xca,%edi
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:101 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex4wake)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:95 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex6unlock)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:746 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1315ed:	48 89 de             	mov    %rbx,%rsi
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:101 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex4wake)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:95 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex6unlock)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:746 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1315f0:	ba 81 00 00 00       	mov    $0x81,%edx
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:101 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex4wake)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:95 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex6unlock)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:746 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1315f5:	b9 01 00 00 00       	mov    $0x1,%ecx
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:101 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex4wake)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:95 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex6unlock)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:746 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1315fa:	31 c0                	xor    %eax,%eax
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:101 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex4wake)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:95 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex6unlock)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:746 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1315fc:	48 83 c4 68          	add    $0x68,%rsp
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:101 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex4wake)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:95 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex6unlock)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:746 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131600:	5b                   	pop    %rbx
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:101 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex4wake)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:95 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex6unlock)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:746 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131601:	41 5c                	pop    %r12
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:101 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex4wake)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:95 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex6unlock)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:746 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131603:	41 5d                	pop    %r13
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:101 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex4wake)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:95 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex6unlock)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:746 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131605:	41 5e                	pop    %r14
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:101 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex4wake)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:95 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex6unlock)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:746 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131607:	41 5f                	pop    %r15
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:101 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex4wake)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:95 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex6unlock)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:746 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131609:	5d                   	pop    %rbp
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:101 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex4wake)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:95 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex6unlock)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:746 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  13160a:	ff 25 e0 f9 11 00    	jmp    *0x11f9e0(%rip)        # 250ff0 <syscall@GLIBC_2.2.5>
<core::result::Result<ed25519::Signature, signature::error::Error>>::map_err::<spiral_protocol::error::Error, <spiral_protocol::identity::ServerIdentity>::sign::{closure#1}>:
/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/result.rs:966
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:79 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131610:	0f 10 44 24 28       	movups 0x28(%rsp),%xmm0
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:79 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131615:	0f 10 4c 24 38       	movups 0x38(%rsp),%xmm1
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:79 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  13161a:	0f 10 54 24 48       	movups 0x48(%rsp),%xmm2
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:79 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  13161f:	0f 10 5c 24 58       	movups 0x58(%rsp),%xmm3
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:79 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131624:	0f 11 58 31          	movups %xmm3,0x31(%rax)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:79 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131628:	0f 11 50 21          	movups %xmm2,0x21(%rax)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:79 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  13162c:	0f 11 48 11          	movups %xmm1,0x11(%rax)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:79 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131630:	0f 11 40 01          	movups %xmm0,0x1(%rax)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:79 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131634:	31 c9                	xor    %ecx,%ecx
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:79 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131636:	88 08                	mov    %cl,(%rax)
<std::sync::poison::Flag>::done:
/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison.rs:126
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:745 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131638:	40 84 ed             	test   %bpl,%bpl
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:745 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  13163b:	75 0c                	jne    131649 <<spiral_protocol::identity::ServerIdentity>::sign+0x1a9>
core::sync::atomic::atomic_load::<usize>:
/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/sync/atomic.rs:3994
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/sync/atomic.rs:2916 (_RNvMs16_NtNtCskADBYZwJmSU_4core4sync6atomicINtB6_6AtomicjE4load)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/panicking.rs:465 (_RNvNtNtCs8ZKwes1zzDd_3std9panicking11panic_count13count_is_zero)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/panicking.rs:606 (_RNvNtCs8ZKwes1zzDd_3std9panicking9panicking)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/thread/functions.rs:221 (_RNvNtNtCs8ZKwes1zzDd_3std6thread9functions9panicking)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison.rs:126 (_RNvMNtNtCs8ZKwes1zzDd_3std4sync6poisonNtB2_4Flag4done)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:745 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  13163d:	49 8b 06             	mov    (%r14),%rax
std::panicking::panic_count::count_is_zero:
/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/panicking.rs:465
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/panicking.rs:606 (_RNvNtCs8ZKwes1zzDd_3std9panicking9panicking)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/thread/functions.rs:221 (_RNvNtNtCs8ZKwes1zzDd_3std6thread9functions9panicking)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison.rs:126 (_RNvMNtNtCs8ZKwes1zzDd_3std4sync6poisonNtB2_4Flag4done)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:745 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131640:	4c 85 f8             	test   %r15,%rax
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/panicking.rs:606 (_RNvNtCs8ZKwes1zzDd_3std9panicking9panicking)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/thread/functions.rs:221 (_RNvNtNtCs8ZKwes1zzDd_3std6thread9functions9panicking)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison.rs:126 (_RNvMNtNtCs8ZKwes1zzDd_3std4sync6poisonNtB2_4Flag4done)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:745 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131643:	0f 85 95 00 00 00    	jne    1316de <<spiral_protocol::identity::ServerIdentity>::sign+0x23e>
core::sync::atomic::atomic_swap::<u32>:
/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/sync/atomic.rs:4013
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/sync/atomic.rs:2977 (_RNvMsQ_NtNtCskADBYZwJmSU_4core4sync6atomicINtB5_6AtomicmE4swap)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:90 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex6unlock)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:746 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131649:	31 c0                	xor    %eax,%eax
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/sync/atomic.rs:2977 (_RNvMsQ_NtNtCskADBYZwJmSU_4core4sync6atomicINtB5_6AtomicmE4swap)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:90 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex6unlock)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:746 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  13164b:	87 03                	xchg   %eax,(%rbx)
<std::sys::sync::mutex::futex::Mutex>::unlock:
/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:90
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:746 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  13164d:	83 f8 02             	cmp    $0x2,%eax
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:746 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131650:	74 55                	je     1316a7 <<spiral_protocol::identity::ServerIdentity>::sign+0x207>
<spiral_protocol::identity::ServerIdentity>::sign:
/tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80
  131652:	48 83 c4 68          	add    $0x68,%rsp
  131656:	5b                   	pop    %rbx
  131657:	41 5c                	pop    %r12
  131659:	41 5d                	pop    %r13
  13165b:	41 5e                	pop    %r14
  13165d:	41 5f                	pop    %r15
  13165f:	5d                   	pop    %rbp
  131660:	c3                   	ret
  131661:	49 89 fe             	mov    %rdi,%r14
std::sys::sync::futex::unix::futex_wake:
/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/futex/unix.rs:97
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:101 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex4wake)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:95 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex6unlock)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:746 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtCs8ZKwes1zzDd_3std4sync6poison11PoisonErrorINtNtBE_5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNCNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB4_14ServerIdentity4sign0B6_)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/result.rs:967 (_RINvMNtCskADBYZwJmSU_4core6resultINtB3_6ResultINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB5_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEINtBN_11PoisonErrorBI_EE7map_errNtNtCs9LFm1b3AnVj_15spiral_protocol5error5ErrorNCNvMNtB3s_8identityNtB4e_14ServerIdentity4sign0EB3s_)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131664:	bf ca 00 00 00       	mov    $0xca,%edi
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:101 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex4wake)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:95 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex6unlock)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:746 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtCs8ZKwes1zzDd_3std4sync6poison11PoisonErrorINtNtBE_5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNCNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB4_14ServerIdentity4sign0B6_)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/result.rs:967 (_RINvMNtCskADBYZwJmSU_4core6resultINtB3_6ResultINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB5_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEINtBN_11PoisonErrorBI_EE7map_errNtNtCs9LFm1b3AnVj_15spiral_protocol5error5ErrorNCNvMNtB3s_8identityNtB4e_14ServerIdentity4sign0EB3s_)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131669:	48 89 de             	mov    %rbx,%rsi
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:101 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex4wake)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:95 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex6unlock)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:746 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtCs8ZKwes1zzDd_3std4sync6poison11PoisonErrorINtNtBE_5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNCNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB4_14ServerIdentity4sign0B6_)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/result.rs:967 (_RINvMNtCskADBYZwJmSU_4core6resultINtB3_6ResultINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB5_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEINtBN_11PoisonErrorBI_EE7map_errNtNtCs9LFm1b3AnVj_15spiral_protocol5error5ErrorNCNvMNtB3s_8identityNtB4e_14ServerIdentity4sign0EB3s_)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  13166c:	ba 81 00 00 00       	mov    $0x81,%edx
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:101 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex4wake)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:95 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex6unlock)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:746 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtCs8ZKwes1zzDd_3std4sync6poison11PoisonErrorINtNtBE_5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNCNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB4_14ServerIdentity4sign0B6_)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/result.rs:967 (_RINvMNtCskADBYZwJmSU_4core6resultINtB3_6ResultINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB5_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEINtBN_11PoisonErrorBI_EE7map_errNtNtCs9LFm1b3AnVj_15spiral_protocol5error5ErrorNCNvMNtB3s_8identityNtB4e_14ServerIdentity4sign0EB3s_)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131671:	b9 01 00 00 00       	mov    $0x1,%ecx
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:101 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex4wake)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:95 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex6unlock)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:746 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtCs8ZKwes1zzDd_3std4sync6poison11PoisonErrorINtNtBE_5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNCNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB4_14ServerIdentity4sign0B6_)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/result.rs:967 (_RINvMNtCskADBYZwJmSU_4core6resultINtB3_6ResultINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB5_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEINtBN_11PoisonErrorBI_EE7map_errNtNtCs9LFm1b3AnVj_15spiral_protocol5error5ErrorNCNvMNtB3s_8identityNtB4e_14ServerIdentity4sign0EB3s_)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131676:	31 c0                	xor    %eax,%eax
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:101 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex4wake)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:95 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex6unlock)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:746 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtCs8ZKwes1zzDd_3std4sync6poison11PoisonErrorINtNtBE_5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNCNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB4_14ServerIdentity4sign0B6_)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/result.rs:967 (_RINvMNtCskADBYZwJmSU_4core6resultINtB3_6ResultINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB5_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEINtBN_11PoisonErrorBI_EE7map_errNtNtCs9LFm1b3AnVj_15spiral_protocol5error5ErrorNCNvMNtB3s_8identityNtB4e_14ServerIdentity4sign0EB3s_)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131678:	ff 15 72 f9 11 00    	call   *0x11f972(%rip)        # 250ff0 <syscall@GLIBC_2.2.5>
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:101 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex4wake)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:95 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex6unlock)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:746 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtCs8ZKwes1zzDd_3std4sync6poison11PoisonErrorINtNtBE_5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNCNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB4_14ServerIdentity4sign0B6_)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/result.rs:967 (_RINvMNtCskADBYZwJmSU_4core6resultINtB3_6ResultINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB5_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEINtBN_11PoisonErrorBI_EE7map_errNtNtCs9LFm1b3AnVj_15spiral_protocol5error5ErrorNCNvMNtB3s_8identityNtB4e_14ServerIdentity4sign0EB3s_)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  13167e:	4c 89 f7             	mov    %r14,%rdi
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:101 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex4wake)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:95 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex6unlock)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:746 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtCs8ZKwes1zzDd_3std4sync6poison11PoisonErrorINtNtBE_5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNCNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB4_14ServerIdentity4sign0B6_)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/result.rs:967 (_RINvMNtCskADBYZwJmSU_4core6resultINtB3_6ResultINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB5_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEINtBN_11PoisonErrorBI_EE7map_errNtNtCs9LFm1b3AnVj_15spiral_protocol5error5ErrorNCNvMNtB3s_8identityNtB4e_14ServerIdentity4sign0EB3s_)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131681:	e9 84 fe ff ff       	jmp    13150a <<spiral_protocol::identity::ServerIdentity>::sign+0x6a>
<std::sync::poison::mutex::MutexGuard<core::option::Option<ed25519_dalek::signing::SigningKey>> as core::ops::drop::Drop>::drop:
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtCs8ZKwes1zzDd_3std4sync6poison11PoisonErrorINtNtBE_5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNCNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB4_14ServerIdentity4sign0B6_)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/result.rs:967 (_RINvMNtCskADBYZwJmSU_4core6resultINtB3_6ResultINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB5_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEINtBN_11PoisonErrorBI_EE7map_errNtNtCs9LFm1b3AnVj_15spiral_protocol5error5ErrorNCNvMNtB3s_8identityNtB4e_14ServerIdentity4sign0EB3s_)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131686:	49 89 f6             	mov    %rsi,%r14
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtCs8ZKwes1zzDd_3std4sync6poison11PoisonErrorINtNtBE_5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNCNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB4_14ServerIdentity4sign0B6_)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/result.rs:967 (_RINvMNtCskADBYZwJmSU_4core6resultINtB3_6ResultINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB5_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEINtBN_11PoisonErrorBI_EE7map_errNtNtCs9LFm1b3AnVj_15spiral_protocol5error5ErrorNCNvMNtB3s_8identityNtB4e_14ServerIdentity4sign0EB3s_)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131689:	49 89 ff             	mov    %rdi,%r15
std::panicking::panic_count::count_is_zero:
/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/panicking.rs:477
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/panicking.rs:606 (_RNvNtCs8ZKwes1zzDd_3std9panicking9panicking)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/thread/functions.rs:221 (_RNvNtNtCs8ZKwes1zzDd_3std6thread9functions9panicking)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison.rs:126 (_RNvMNtNtCs8ZKwes1zzDd_3std4sync6poisonNtB2_4Flag4done)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:745 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtCs8ZKwes1zzDd_3std4sync6poison11PoisonErrorINtNtBE_5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNCNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB4_14ServerIdentity4sign0B6_)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/result.rs:967 (_RINvMNtCskADBYZwJmSU_4core6resultINtB3_6ResultINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB5_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEINtBN_11PoisonErrorBI_EE7map_errNtNtCs9LFm1b3AnVj_15spiral_protocol5error5ErrorNCNvMNtB3s_8identityNtB4e_14ServerIdentity4sign0EB3s_)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  13168c:	ff 15 be fd 11 00    	call   *0x11fdbe(%rip)        # 251450 <_DYNAMIC+0xbc8>
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/panicking.rs:606 (_RNvNtCs8ZKwes1zzDd_3std9panicking9panicking)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/thread/functions.rs:221 (_RNvNtNtCs8ZKwes1zzDd_3std6thread9functions9panicking)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison.rs:126 (_RNvMNtNtCs8ZKwes1zzDd_3std4sync6poisonNtB2_4Flag4done)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:745 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtCs8ZKwes1zzDd_3std4sync6poison11PoisonErrorINtNtBE_5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNCNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB4_14ServerIdentity4sign0B6_)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/result.rs:967 (_RINvMNtCskADBYZwJmSU_4core6resultINtB3_6ResultINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB5_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEINtBN_11PoisonErrorBI_EE7map_errNtNtCs9LFm1b3AnVj_15spiral_protocol5error5ErrorNCNvMNtB3s_8identityNtB4e_14ServerIdentity4sign0EB3s_)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131692:	4c 89 ff             	mov    %r15,%rdi
<std::sync::poison::Flag>::done:
/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison.rs:126
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:745 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtCs8ZKwes1zzDd_3std4sync6poison11PoisonErrorINtNtBE_5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNCNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB4_14ServerIdentity4sign0B6_)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/result.rs:967 (_RINvMNtCskADBYZwJmSU_4core6resultINtB3_6ResultINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB5_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEINtBN_11PoisonErrorBI_EE7map_errNtNtCs9LFm1b3AnVj_15spiral_protocol5error5ErrorNCNvMNtB3s_8identityNtB4e_14ServerIdentity4sign0EB3s_)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131695:	84 c0                	test   %al,%al
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:745 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtCs8ZKwes1zzDd_3std4sync6poison11PoisonErrorINtNtBE_5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNCNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB4_14ServerIdentity4sign0B6_)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/result.rs:967 (_RINvMNtCskADBYZwJmSU_4core6resultINtB3_6ResultINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB5_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEINtBN_11PoisonErrorBI_EE7map_errNtNtCs9LFm1b3AnVj_15spiral_protocol5error5ErrorNCNvMNtB3s_8identityNtB4e_14ServerIdentity4sign0EB3s_)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  131697:	0f 85 60 fe ff ff    	jne    1314fd <<spiral_protocol::identity::ServerIdentity>::sign+0x5d>
core::sync::atomic::atomic_store::<u8>:
/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/sync/atomic.rs:3978
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/sync/atomic.rs:793 (_RNvMs2_NtNtCskADBYZwJmSU_4core4sync6atomicINtB5_6AtomicbE5store)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison.rs:127 (_RNvMNtNtCs8ZKwes1zzDd_3std4sync6poisonNtB2_4Flag4done)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:745 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtCs8ZKwes1zzDd_3std4sync6poison11PoisonErrorINtNtBE_5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNCNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB4_14ServerIdentity4sign0B6_)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/result.rs:967 (_RINvMNtCskADBYZwJmSU_4core6resultINtB3_6ResultINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB5_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEINtBN_11PoisonErrorBI_EE7map_errNtNtCs9LFm1b3AnVj_15spiral_protocol5error5ErrorNCNvMNtB3s_8identityNtB4e_14ServerIdentity4sign0EB3s_)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  13169d:	41 c6 46 24 01       	movb   $0x1,0x24(%r14)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/sync/atomic.rs:793 (_RNvMs2_NtNtCskADBYZwJmSU_4core4sync6atomicINtB5_6AtomicbE5store)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison.rs:127 (_RNvMNtNtCs8ZKwes1zzDd_3std4sync6poisonNtB2_4Flag4done)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:745 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtCs8ZKwes1zzDd_3std4sync6poison11PoisonErrorINtNtBE_5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNCNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB4_14ServerIdentity4sign0B6_)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/result.rs:967 (_RINvMNtCskADBYZwJmSU_4core6resultINtB3_6ResultINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB5_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEINtBN_11PoisonErrorBI_EE7map_errNtNtCs9LFm1b3AnVj_15spiral_protocol5error5ErrorNCNvMNtB3s_8identityNtB4e_14ServerIdentity4sign0EB3s_)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:74 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1316a2:	e9 56 fe ff ff       	jmp    1314fd <<spiral_protocol::identity::ServerIdentity>::sign+0x5d>
std::sys::sync::futex::unix::futex_wake:
/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/futex/unix.rs:97
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:101 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex4wake)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:95 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex6unlock)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:746 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1316a7:	bf ca 00 00 00       	mov    $0xca,%edi
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:101 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex4wake)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:95 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex6unlock)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:746 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1316ac:	48 89 de             	mov    %rbx,%rsi
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:101 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex4wake)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:95 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex6unlock)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:746 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1316af:	ba 81 00 00 00       	mov    $0x81,%edx
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:101 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex4wake)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:95 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex6unlock)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:746 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1316b4:	b9 01 00 00 00       	mov    $0x1,%ecx
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:101 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex4wake)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:95 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex6unlock)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:746 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1316b9:	31 c0                	xor    %eax,%eax
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:101 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex4wake)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:95 (_RNvMNtNtNtNtCs8ZKwes1zzDd_3std3sys4sync5mutex5futexNtB2_5Mutex6unlock)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:746 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1316bb:	ff 15 2f f9 11 00    	call   *0x11f92f(%rip)        # 250ff0 <syscall@GLIBC_2.2.5>
<std::sys::sync::mutex::futex::Mutex>::unlock:
/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sys/sync/mutex/futex.rs:95
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:746 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1316c1:	eb 8f                	jmp    131652 <<spiral_protocol::identity::ServerIdentity>::sign+0x1b2>
<spiral_protocol::identity::ServerIdentity>::sign:
  1316c3:	49 89 f6             	mov    %rsi,%r14
std::panicking::panic_count::count_is_zero:
/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/panicking.rs:477
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/panicking.rs:606 (_RNvNtCs8ZKwes1zzDd_3std9panicking9panicking)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/thread/functions.rs:221 (_RNvNtNtCs8ZKwes1zzDd_3std6thread9functions9panicking)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison.rs:126 (_RNvMNtNtCs8ZKwes1zzDd_3std4sync6poisonNtB2_4Flag4done)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:745 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1316c6:	ff 15 84 fd 11 00    	call   *0x11fd84(%rip)        # 251450 <_DYNAMIC+0xbc8>
<std::sync::poison::Flag>::done:
/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison.rs:126
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:745 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1316cc:	84 c0                	test   %al,%al
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:745 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1316ce:	0f 85 0b ff ff ff    	jne    1315df <<spiral_protocol::identity::ServerIdentity>::sign+0x13f>
core::sync::atomic::atomic_store::<u8>:
/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/sync/atomic.rs:3978
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/sync/atomic.rs:793 (_RNvMs2_NtNtCskADBYZwJmSU_4core4sync6atomicINtB5_6AtomicbE5store)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison.rs:127 (_RNvMNtNtCs8ZKwes1zzDd_3std4sync6poisonNtB2_4Flag4done)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:745 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1316d4:	41 c6 46 24 01       	movb   $0x1,0x24(%r14)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/sync/atomic.rs:793 (_RNvMs2_NtNtCskADBYZwJmSU_4core4sync6atomicINtB5_6AtomicbE5store)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison.rs:127 (_RNvMNtNtCs8ZKwes1zzDd_3std4sync6poisonNtB2_4Flag4done)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:745 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1316d9:	e9 01 ff ff ff       	jmp    1315df <<spiral_protocol::identity::ServerIdentity>::sign+0x13f>
std::panicking::panic_count::count_is_zero:
/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/panicking.rs:477
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/panicking.rs:606 (_RNvNtCs8ZKwes1zzDd_3std9panicking9panicking)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/thread/functions.rs:221 (_RNvNtNtCs8ZKwes1zzDd_3std6thread9functions9panicking)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison.rs:126 (_RNvMNtNtCs8ZKwes1zzDd_3std4sync6poisonNtB2_4Flag4done)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:745 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1316de:	ff 15 6c fd 11 00    	call   *0x11fd6c(%rip)        # 251450 <_DYNAMIC+0xbc8>
<std::sync::poison::Flag>::done:
/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison.rs:126
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:745 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1316e4:	84 c0                	test   %al,%al
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:745 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1316e6:	0f 85 5d ff ff ff    	jne    131649 <<spiral_protocol::identity::ServerIdentity>::sign+0x1a9>
core::sync::atomic::atomic_store::<u8>:
/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/sync/atomic.rs:3978
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/sync/atomic.rs:793 (_RNvMs2_NtNtCskADBYZwJmSU_4core4sync6atomicINtB5_6AtomicbE5store)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison.rs:127 (_RNvMNtNtCs8ZKwes1zzDd_3std4sync6poisonNtB2_4Flag4done)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:745 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1316ec:	41 c6 44 24 24 01    	movb   $0x1,0x24(%r12)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/sync/atomic.rs:793 (_RNvMs2_NtNtCskADBYZwJmSU_4core4sync6atomicINtB5_6AtomicbE5store)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison.rs:127 (_RNvMNtNtCs8ZKwes1zzDd_3std4sync6poisonNtB2_4Flag4done)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/std/src/sync/poison/mutex.rs:745 (_RNvXsc_NtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutexINtB5_10MutexGuardINtNtCskADBYZwJmSU_4core6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEENtNtNtB18_3ops4drop4Drop4dropCs9LFm1b3AnVj_15spiral_protocol)
inlined by /rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library/core/src/ptr/mod.rs:847 (_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtNtNtCs8ZKwes1zzDd_3std4sync6poison5mutex10MutexGuardINtNtB4_6option6OptionNtNtCsgxmkeHbIDMv_13ed25519_dalek7signing10SigningKeyEEECs9LFm1b3AnVj_15spiral_protocol)
inlined by /tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80 (_RNvMNtCs9LFm1b3AnVj_15spiral_protocol8identityNtB2_14ServerIdentity4sign)
  1316f2:	e9 52 ff ff ff       	jmp    131649 <<spiral_protocol::identity::ServerIdentity>::sign+0x1a9>
<spiral_protocol::identity::ServerIdentity>::sign:
  1316f7:	48 89 c3             	mov    %rax,%rbx
  1316fa:	48 89 e7             	mov    %rsp,%rdi
/tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:80
  1316fd:	e8 0e be f9 ff       	call   cd510 <core::ptr::drop_glue::<std::sync::poison::PoisonError<std::sync::poison::mutex::MutexGuard<core::option::Option<std::time::Instant>>>>>
  131702:	48 89 df             	mov    %rbx,%rdi
  131705:	e8 d6 b2 10 00       	call   23c9e0 <_Unwind_Resume@plt>
/tmp/secret-copy-package-test/Spiral-secret-copy-7f26fed/source/protocol_rust/src/identity.rs:73
  13170a:	ff 15 48 f4 11 00    	call   *0x11f448(%rip)        # 250b58 <_DYNAMIC+0x2d0>
