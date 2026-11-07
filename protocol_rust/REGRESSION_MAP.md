# Python baseline tests and Rust correspondence map v0.3

We compared all 85 Python methods on the baseline main branch line by line. Passing baseline Python tests is not added to the Rust test pass count.

There are 72 corresponding tests, 8 correspondences through ownership/type structure, and 5 partial correspondences. `tested` also does not mean that the entire original input enumeration is identical. Partial correspondences specify unported scenarios and differences in API semantics.

Execution results: 52 Rust unit tests + 4 compile-fail tests, 35 real TLS tests. The 2 dynamic taint tests were excluded from the regular unit run and instrumented separately. Machine-readable data is in `REGRESSION_MAP.json`.

## test_adversarial.py

| Python method | Category | Rust evidence | Scope/differences |
|---|---|---|---|
| `test_every_truncated_frame_rejected` | Corresponding test | `protocol_rust/src/wire.rs::all_fixture_roundtrips_and_truncations` | Runtime check of this requirement |
| `test_all_header_bits_rejected_under_connection_expectations` | Corresponding test | `protocol_rust/src/wire.rs::every_header_bit_under_connection_expectation` | Runtime check of this requirement |
| `test_all_data_frame_bits_fail_without_plaintext_release` | Corresponding test | `protocol_rust/src/records.rs::every_record_bit_tamper_poisoned` | Runtime check of this requirement |
| `test_seeded_frame_mutation_corpus_is_canonical_if_accepted` | Corresponding test | `protocol_rust/src/wire.rs::deterministic_mutation_corpus_canonical_if_accepted` | Runtime check of this requirement |
| `test_length_bomb_rejected_before_payload_read` | Corresponding test | `protocol_rust/src/transport.rs::invalid_length_never_reaches_payload_read`; `protocol_rust/interop.py::test_length_bomb` | Runtime check of this requirement |
| `test_clienthello_grammar_mutations_rejected` | Corresponding test | `protocol_rust/src/handshake.rs::identities_and_hello_grammar` | Runtime check of this requirement |
| `test_finished_each_byte_tampering_has_no_server_finished` | Corresponding test | `protocol_rust/src/handshake.rs::finished_each_byte_and_changed_ct_rejected` | Runtime check of this requirement |
| `test_chosen_canonical_ciphertexts_cannot_retry_key` | Corresponding test | `protocol_rust/src/worker.rs::malformed_ct_consumes_native_key`; `protocol_rust/adversarial.py::test_independent_duplicate_clientkey_never_decapsulates_twice`; `protocol_rust/adversarial.py::test_independent_canonical_changed_ciphertext_never_establishes` | Runtime check of this requirement |
| `test_duplicate_data_permanently_invalidates_receiver` | Corresponding test | `protocol_rust/src/records.rs::duplicate_and_out_of_order_rejected` | Runtime check of this requirement |
| `test_nonce_reservations_unique_under_parallel_encoding` | Corresponding test | `protocol_rust/interop.py::test_rust_to_rust_sizes_and_parallel_senders` | Runtime check of this requirement |

## test_channel.py

| Python method | Category | Rust evidence | Scope/differences |
|---|---|---|---|
| `test_peer_close_aborts_blocked_writer_at_close_queue_deadline` | Partial correspondence | `protocol_rust/src/channel.rs::partial_write_deadline_cannot_be_extended_by_activity`; `protocol_rust/src/channel.rs::close_and_failure_have_finite_deadlines` | Partial writes and shutdown were verified separately. The original injection of a stalled final CLOSE write is not yet equivalent. |
| `test_tls_shutdown_waits_for_complete_final_close_write` | Corresponding test | `protocol_rust/adversarial.py::test_independent_peer_boundary_data_and_authenticated_close`; `protocol_rust/src/channel.rs::failed_partial_transport_cannot_retry_or_roll_back_nonce`; `protocol_rust/src/channel.rs::authenticated_close_finishes_before_transport_shutdown` | Runtime check of this requirement |
| `test_failed_send_aborts_and_cannot_retry_reserved_nonce` | Corresponding test | `protocol_rust/src/channel.rs::failed_partial_transport_cannot_retry_or_roll_back_nonce` | Runtime check of this requirement |
| `test_concurrent_send_queue_preserves_encode_and_wire_order` | Corresponding test | `protocol_rust/interop.py::test_rust_to_rust_sizes_and_parallel_senders` | Runtime check of this requirement |

## test_core.py

| Python method | Category | Rust evidence | Scope/differences |
|---|---|---|---|
| `test_client_matches_supplied_vectors` | Corresponding test | `protocol_rust/src/handshake.rs::original_signature_and_clienthello`; `protocol_rust/src/schedule.rs::original_key_schedule_vector`; `protocol_rust/src/records.rs::both_directions_match_vectors_and_reject_data_after_close` | Runtime check of this requirement |
| `test_server_matches_supplied_vectors_and_releases_live_id` | Corresponding test | `protocol_rust/src/handshake.rs::original_signature_and_clienthello`; `protocol_rust/src/handshake.rs::valid_server_state_and_exporter_mismatch`; `protocol_rust/src/handshake.rs::valid_server_state_and_exporter_mismatch` | Runtime check of this requirement |
| `test_scoped_pins_rejected_before_kem` | Corresponding test | `protocol_rust/interop.py::test_wrong_pin_expired_and_revoked`; `protocol_rust/adversarial.py::test_independent_wrong_service_rejected_before_keygen` | Runtime check of this requirement |
| `test_server_bad_binding_or_service_before_kem` | Corresponding test | `protocol_rust/adversarial.py::test_independent_wrong_binding_rejected_before_keygen`; `protocol_rust/adversarial.py::test_independent_wrong_service_rejected_before_keygen` | Runtime check of this requirement |
| `test_invalid_signature_before_kem` | Corresponding test | `protocol_rust/adversarial.py::test_invalid_server_signature_rejected_before_encapsulation` | Runtime check of this requirement |
| `test_core_checks_finished` | Corresponding test | `protocol_rust/interop.py::test_server_finished_rejected_before_data`; `protocol_rust/src/handshake.rs::finished_each_byte_and_changed_ct_rejected` | Runtime check of this requirement |
| `test_server_bad_cf_and_ciphertext_are_one_shot` | Corresponding test | `protocol_rust/adversarial.py::test_independent_forged_client_finished_never_establishes`; `protocol_rust/adversarial.py::test_independent_canonical_changed_ciphertext_never_establishes`; `protocol_rust/adversarial.py::test_independent_duplicate_clientkey_never_decapsulates_twice` | Runtime check of this requirement |
| `test_one_shot_consumed_after_failure` | Structural correspondence | `protocol_rust/src/worker.rs::malformed_ct_consumes_native_key`; `protocol_rust/src/ffi.rs::NativeKey` | Rust ownership/build hash guards replace the Python object reentry/source guards. |
| `test_concurrent_server_owner_and_late_receive_fail_closed` | Structural correspondence | `protocol_rust/src/handshake.rs::server`; `protocol_rust/src/handshake.rs::transport_failure_and_canceled_handshake_release_native_key` | Rust ownership/build hash guards replace the Python object reentry/source guards. |
| `test_successful_server_cannot_retry_or_reset_counter` | Corresponding test | `protocol_rust/adversarial.py::test_independent_duplicate_clientkey_never_decapsulates_twice`; `protocol_rust/adversarial.py::test_independent_valid_record_replay_delivers_only_once` | Runtime check of this requirement |
| `test_expired_deadline_before_work` | Corresponding test | `protocol_rust/src/worker.rs::queued_deadline_and_canceled_lease_cleanup`; `protocol_rust/src/worker.rs::wrong_pool_and_expired_leases_never_reuse_a_key` | Runtime check of this requirement |
| `test_kem_source_guard` | Structural correspondence | `protocol_rust/build.rs` | Rust ownership/build hash guards replace the Python object reentry/source guards. |
| `test_ch_grammar` | Corresponding test | `protocol_rust/src/handshake.rs::identities_and_hello_grammar` | Runtime check of this requirement |
| `test_semantic_header_gaps_are_rejected` | Corresponding test | `protocol_rust/src/wire.rs::every_header_bit_under_connection_expectation`; `protocol_rust/src/wire.rs::length_bombs_and_reserved_close` | Runtime check of this requirement |
| `test_all_fixture_frames_roundtrip` | Corresponding test | `protocol_rust/src/wire.rs::all_fixture_roundtrips_and_truncations` | Runtime check of this requirement |

## test_independent_peer.py

| Python method | Category | Rust evidence | Scope/differences |
|---|---|---|---|
| `test_independent_peer_boundary_data_and_authenticated_close` | Corresponding test | `protocol_rust/adversarial.py::test_independent_peer_boundary_data_and_authenticated_close` | Runtime check of this requirement |
| `test_new_connections_change_session_exporter_and_kem_key` | Corresponding test | `protocol_rust/adversarial.py::test_independent_new_connections_change_exporter_session_and_kem_key` | Runtime check of this requirement |
| `test_wrong_binding_rejected_before_keygen` | Corresponding test | `protocol_rust/adversarial.py::test_independent_wrong_binding_rejected_before_keygen` | Runtime check of this requirement |
| `test_wrong_scoped_service_rejected_before_keygen` | Corresponding test | `protocol_rust/adversarial.py::test_independent_wrong_service_rejected_before_keygen` | Runtime check of this requirement |
| `test_untrusted_additional_signing_pin_is_rejected` | Corresponding test | `protocol_rust/adversarial.py::test_independent_untrusted_signing_pin_is_rejected` | Runtime check of this requirement |
| `test_forged_client_finished_never_establishes` | Corresponding test | `protocol_rust/adversarial.py::test_independent_forged_client_finished_never_establishes` | Runtime check of this requirement |
| `test_canonical_changed_ciphertext_never_establishes` | Corresponding test | `protocol_rust/adversarial.py::test_independent_canonical_changed_ciphertext_never_establishes` | Runtime check of this requirement |
| `test_early_data_never_decapsulates_or_delivers` | Corresponding test | `protocol_rust/adversarial.py::test_independent_early_data_never_decapsulates` | Runtime check of this requirement |
| `test_previous_session_clientkey_is_rejected` | Corresponding test | `protocol_rust/adversarial.py::test_independent_previous_session_clientkey_is_rejected` | Runtime check of this requirement |
| `test_duplicate_clientkey_after_established_is_rejected` | Corresponding test | `protocol_rust/adversarial.py::test_independent_duplicate_clientkey_never_decapsulates_twice` | Runtime check of this requirement |
| `test_skipped_sequence_has_no_plaintext_delivery` | Corresponding test | `protocol_rust/adversarial.py::test_independent_skipped_sequence_has_no_delivery` | Runtime check of this requirement |
| `test_valid_record_replay_delivers_only_once` | Corresponding test | `protocol_rust/adversarial.py::test_independent_valid_record_replay_delivers_only_once` | Runtime check of this requirement |
| `test_bad_tag_has_no_plaintext_delivery` | Corresponding test | `protocol_rust/adversarial.py::test_independent_bad_tag_has_no_delivery` | Runtime check of this requirement |
| `test_wrong_direction_has_no_plaintext_delivery` | Corresponding test | `protocol_rust/adversarial.py::test_independent_wrong_direction_has_no_delivery` | Runtime check of this requirement |
| `test_truncated_clientkey_claims_opportunity_without_decapsulation` | Corresponding test | `protocol_rust/adversarial.py::test_independent_truncated_clientkey_never_decapsulates` | Runtime check of this requirement |
| `test_eof_without_spiral_close_is_not_clean_shutdown` | Corresponding test | `protocol_rust/adversarial.py::test_independent_eof_without_authenticated_close_is_not_clean` | Runtime check of this requirement |

## test_records.py

| Python method | Category | Rust evidence | Scope/differences |
|---|---|---|---|
| `test_supplied_record_vectors_match_both_roles_byte_for_byte` | Corresponding test | `protocol_rust/src/records.rs::both_directions_match_vectors_and_reject_data_after_close` | Runtime check of this requirement |
| `test_bidirectional_data_and_authenticated_close` | Corresponding test | `protocol_rust/interop.py::test_python_to_rust_four_sessions`; `protocol_rust/interop.py::test_rust_to_python_four_sessions` | Runtime check of this requirement |
| `test_local_close_allows_peer_inflight_data_until_peer_close` | Partial correspondence | `protocol_rust/src/channel.rs::authenticated_queued_data_survives_clean_close` | Tests delivery of DATA already authenticated and queued. Application delivery semantics for in-flight DATA arriving after CLOSE differ from the Python record API. |
| `test_peer_close_blocks_new_local_data` | Structural correspondence | `protocol_rust/src/channel.rs::close`; `protocol_rust/src/channel.rs::Sender` | The shared Life state blocks Sender. Individual transition injection tests for local/remote CLOSE are not equivalent. |
| `test_local_duplicate_close_is_fatal` | Partial correspondence | `protocol_rust/src/records.rs::encode_matches_fixture_and_reserves_close` | An individual Tx rejects a second CLOSE, but Session.close is an idempotent shutdown API. |
| `test_peer_data_after_close_is_fatal` | Corresponding test | `protocol_rust/src/records.rs::both_directions_match_vectors_and_reject_data_after_close` | Runtime check of this requirement |
| `test_unknown_authenticated_close_reason_is_fatal` | Corresponding test | `protocol_rust/src/records.rs::authenticated_unknown_close_and_receive_byte_overrun_poison_keys`; `protocol_rust/adversarial.py::test_independent_authenticated_unknown_close_reason_is_rejected` | Runtime check of this requirement |
| `test_empty_oversized_and_wrong_type_data_are_fatal` | Partial correspondence | `protocol_rust/src/wire.rs::length_bombs_and_reserved_close`; `protocol_rust/src/records.rs::Tx`; `protocol_rust/src/channel.rs::Sender` | Invalid wire lengths/types and authenticated close reasons are rejected. Invalid local input to Rust Sender produces an Input error before transmission and does not replicate all fatal semantics of the Python API. |
| `test_maximum_data_roundtrip` | Corresponding test | `protocol_rust/adversarial.py::test_independent_peer_boundary_data_and_authenticated_close` | Runtime check of this requirement |
| `test_ciphertext_tag_header_identity_and_sequence_tampering` | Corresponding test | `protocol_rust/src/records.rs::every_record_bit_tamper_poisoned` | Runtime check of this requirement |
| `test_reflection_skipped_sequence_and_nonrecord_frame` | Corresponding test | `protocol_rust/adversarial.py::test_independent_wrong_direction_has_no_delivery`; `protocol_rust/adversarial.py::test_independent_skipped_sequence_has_no_delivery`; `protocol_rust/adversarial.py::test_independent_duplicate_clientkey_never_decapsulates_twice` | Runtime check of this requirement |
| `test_duplicate_decode_atomic_one_delivery_then_permanent_failure` | Corresponding test | `protocol_rust/src/records.rs::duplicate_and_out_of_order_rejected`; `protocol_rust/adversarial.py::test_independent_valid_record_replay_delivers_only_once` | Runtime check of this requirement |
| `test_concurrent_encodes_have_unique_reserved_sequences` | Corresponding test | `protocol_rust/interop.py::test_rust_to_rust_sizes_and_parallel_senders` | Runtime check of this requirement |
| `test_encryption_exception_burns_sequence_and_cannot_retry` | Corresponding test | `protocol_rust/src/records.rs::failed_encryption_burns_sequence_and_cannot_retry` | Runtime check of this requirement |
| `test_cancellation_during_encrypt_burns_sequence_and_drops_keys` | Structural correspondence | `protocol_rust/src/records.rs::Tx`; `protocol_rust/src/channel.rs::write_loop`; `protocol_rust/src/secret.rs::canceled_task_wipes_its_owned_secret` | AEAD encode is a synchronous operation with a single owner and no await. It introduces no intermediate task cancellation point. |
| `test_abort_after_failed_transport_has_no_nonce_rollback` | Corresponding test | `protocol_rust/src/channel.rs::failed_partial_transport_cannot_retry_or_roll_back_nonce` | Runtime check of this requirement |
| `test_final_record_sequence_reserved_for_close` | Corresponding test | `protocol_rust/src/records.rs::count_and_byte_limits_still_allow_close` | Runtime check of this requirement |
| `test_incoming_data_on_reserved_close_sequence_is_fatal` | Corresponding test | `protocol_rust/src/wire.rs::length_bombs_and_reserved_close` | Runtime check of this requirement |
| `test_data_byte_budget_preserves_one_byte_close` | Corresponding test | `protocol_rust/src/records.rs::count_and_byte_limits_still_allow_close` | Runtime check of this requirement |
| `test_receive_byte_budget_overrun_is_fatal` | Corresponding test | `protocol_rust/src/records.rs::authenticated_unknown_close_and_receive_byte_overrun_poison_keys` | Runtime check of this requirement |
| `test_idle_expiry_blocks_retries_but_allows_close_within_grace` | Corresponding test | `protocol_rust/src/channel.rs::age_idle_and_close_deadlines_remain_independent`; `protocol_rust/src/channel.rs::close_and_failure_have_finite_deadlines`; `protocol_rust/src/channel.rs::age_idle_and_close_deadlines_remain_independent` | Expiry tests inject owned timestamps and verify termination of the actual I/O loop. |
| `test_age_expiry_independent_of_recent_activity` | Corresponding test | `protocol_rust/src/channel.rs::age_idle_and_close_deadlines_remain_independent`; `protocol_rust/src/channel.rs::age_idle_and_close_deadlines_remain_independent` | Expiry tests inject owned timestamps and verify termination of the actual I/O loop. |
| `test_close_grace_expiry_is_fatal` | Corresponding test | `protocol_rust/src/channel.rs::age_idle_and_close_deadlines_remain_independent`; `protocol_rust/src/channel.rs::age_idle_and_close_deadlines_remain_independent` | Expiry tests inject owned timestamps and verify termination of the actual I/O loop. |
| `test_io_deadline_tracks_idle_age_and_closing_grace` | Corresponding test | `protocol_rust/src/channel.rs::age_idle_and_close_deadlines_remain_independent`; `protocol_rust/src/channel.rs::partial_write_deadline_cannot_be_extended_by_activity` | Runtime check of this requirement |
| `test_wrong_wire_type_and_invalid_reason_are_fatal` | Partial correspondence | `protocol_rust/src/wire.rs::length_bombs_and_reserved_close`; `protocol_rust/src/records.rs::authenticated_unknown_close_and_receive_byte_overrun_poison_keys` | Invalid wire lengths/types and authenticated close reasons are rejected. Invalid local input to Rust Sender produces an Input error before transmission and does not replicate all fatal semantics of the Python API. |

## test_tls.py

| Python method | Category | Rust evidence | Scope/differences |
|---|---|---|---|
| `test_real_tls13_matching_exporter_and_new_connection_uniqueness` | Corresponding test | `protocol_rust/adversarial.py::test_independent_new_connections_change_exporter_session_and_kem_key`; `protocol_rust/interop.py::test_python_to_rust_four_sessions` | Runtime check of this requirement |
| `test_wrong_ca_rejected` | Corresponding test | `protocol_rust/interop.py::test_untrusted_tls_ca` | Runtime check of this requirement |
| `test_wrong_hostname_rejected` | Corresponding test | `protocol_rust/interop.py::test_wrong_tls_hostname` | Runtime check of this requirement |
| `test_wrong_alpn_rejected` | Corresponding test | `protocol_rust/interop.py::test_wrong_alpn` | Runtime check of this requirement |
| `test_tls12_rejected` | Corresponding test | `protocol_rust/adversarial.py::test_tls12_is_rejected_before_inner_kem` | Runtime check of this requirement |
| `test_expired_certificate_rejected` | Corresponding test | `protocol_rust/adversarial.py::test_expired_tls_certificate_is_rejected_before_inner_kem` | Runtime check of this requirement |
| `test_fragmented_and_coalesced_frames_preserve_exact_boundaries` | Corresponding test | `protocol_rust/src/channel.rs::partial_reads_keep_progress_across_notifications`; `protocol_rust/interop.py::test_rust_to_rust_sizes_and_parallel_senders` | Runtime check of this requirement |
| `test_partial_header_timeout_permanently_closes_and_releases_once` | Corresponding test | `protocol_rust/src/handshake.rs::transport_failure_and_canceled_handshake_release_native_key`; `protocol_rust/interop.py::test_truncated_record`; `protocol_rust/src/channel.rs::slow_header_cannot_extend_deadline_or_deliver_after_expiry` | Runtime check of this requirement |
| `test_slow_header_dribble_does_not_extend_absolute_deadline` | Corresponding test | `protocol_rust/src/channel.rs::partial_reads_keep_progress_across_notifications`; `protocol_rust/src/channel.rs::partial_write_deadline_cannot_be_extended_by_activity`; `protocol_rust/src/channel.rs::slow_header_cannot_extend_deadline_or_deliver_after_expiry` | Runtime check of this requirement |
| `test_concurrent_reader_attempt_closes_connection` | Structural correspondence | `protocol_rust/src/channel.rs::Session`; `protocol_rust/src/transport.rs::FrameIo` | A dedicated reader task/exclusive &mut borrow and RAII ownership replace Python's dynamic reader/callback API. |
| `test_clientkey_header_claims_key_before_payload_and_timeout_never_revives` | Structural correspondence | `protocol_rust/adversarial.py::test_independent_truncated_clientkey_never_decapsulates`; `protocol_rust/src/handshake.rs::transport_failure_and_canceled_handshake_release_native_key` | Rust consumes the lease after receiving a complete CK. Incomplete input ends with disposal of the connection/lease; it does not use the original header-time claim API as-is. |
| `test_duplicate_clientkey_header_rejected_before_second_payload` | Corresponding test | `protocol_rust/adversarial.py::test_independent_duplicate_clientkey_never_decapsulates_twice`; `protocol_rust/src/transport.rs::read_record` | Runtime check of this requirement |
| `test_close_callback_registration_concurrent_with_close_exactly_once` | Structural correspondence | `protocol_rust/src/admission.rs::bounds_and_release`; `protocol_rust/src/worker.rs::concurrent_shutdown_waits_even_if_first_caller_is_canceled` | A dedicated reader task/exclusive &mut borrow and RAII ownership replace Python's dynamic reader/callback API. |
| `test_ipv4_mapped_ipv6_same_peer_connection_limit_and_bucket` | Corresponding test | `protocol_rust/src/admission.rs::mapped_ip_and_pending_cap` | Runtime check of this requirement |
| `test_global_pending_32_then_established_active_64` | Corresponding test | `protocol_rust/src/admission.rs::mapped_ip_and_pending_cap` | Runtime check of this requirement |

