#!/usr/bin/env python3
"""Collector contract tests; no TLS probe, credentials, or soak are started."""
import importlib.util
import math
import os
from pathlib import Path
import sys
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "load_campaign_under_test", Path(__file__).with_name("load_campaign.py"))
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)


def completed_report(connections=64):
    # Three epochs exercise accounting for all pairs, not just peak concurrency.
    pairs = connections * 3
    return {
        "status": "passed",
        "soak_elapsed_seconds": 1800,
        "traffic_epoch_elapsed_seconds": 1800,
        "total_messages": connections,
        "peak_authenticated_connections": connections,
        "active": 0,
        "pending": 0,
        "admission_released": True,
        "kem": {"live_keys": 0, "executed_jobs": pairs * 3},
        "authenticated_close_for_all_completed_pairs": True,
        "auth_key_closed": True,
        "authenticated_pairs_total": pairs,
        "authenticated_pair_closes": pairs,
        "successful_endpoint_handshakes": pairs * 2,
        "resource_baseline": {"fd_count": 16},
        "final_resources": {"fd_count": 15},
        "errors": [],
        "limit_checks": {"per_ip": True, "pending": True, "global": True},
    }


class StrictJsonContracts(unittest.TestCase):
    def test_accepts_finite_values_and_distinct_nested_objects(self):
        value = collector.strict_json(
            b'{"samples":[{"count":0},{"count":1}],"elapsed":1800.5,"label":"NaN"}')
        self.assertEqual(value["samples"], [{"count": 0}, {"count": 1}])
        self.assertEqual(value["elapsed"], 1800.5)
        self.assertEqual(value["label"], "NaN")

    def test_rejects_duplicate_keys_at_every_depth(self):
        for document in (
            '{"status":"passed","status":"failed"}',
            '{"kem":{"live_keys":0,"live_keys":1}}',
            '{"samples":[{"pending":true,"pending":false}]}',
        ):
            with self.subTest(document=document):
                with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                    collector.strict_json(document)

    def test_rejects_nonfinite_literals_and_float_overflow(self):
        for number in ("NaN", "Infinity", "-Infinity", "1e999", "-1e999"):
            for document in (number, '{"elapsed":' + number + '}'):
                with self.subTest(document=document):
                    with self.assertRaises(ValueError):
                        collector.strict_json(document)


class FinalReportContracts(unittest.TestCase):
    def validate(self, report, connections=64):
        return collector.validate_final(report, 1800, connections)

    def test_accepts_complete_64_connection_report_at_requested_duration(self):
        self.assertIsNone(self.validate(completed_report()))

    def test_accepts_descriptor_recovery_below_baseline(self):
        report = completed_report()
        report["final_resources"]["fd_count"] -= 1
        self.assertIsNone(self.validate(report))

    def test_global_cap_check_is_required_only_for_64_connections(self):
        report = completed_report(32)
        del report["limit_checks"]["global"]
        self.assertIsNone(self.validate(report, 32))

    def test_rejects_missing_or_failed_final_result(self):
        for report in (None, [], {}, {"status": "failed"}):
            with self.subTest(report=report):
                with self.assertRaisesRegex(ValueError, "passed final result"):
                    self.validate(report)

    def test_rejects_short_or_nonfinite_soak_and_traffic_duration(self):
        for key in ("soak_elapsed_seconds", "traffic_epoch_elapsed_seconds"):
            for value in (1799.999, None, True, float("nan"), float("inf")):
                report = completed_report()
                report[key] = value
                with self.subTest(key=key, value=value):
                    with self.assertRaisesRegex(ValueError, "shorter than requested"):
                        self.validate(report)

    def test_rejects_missing_echo_traffic_or_requested_concurrency(self):
        for value in (0, 63, None, True, float("inf")):
            report = completed_report()
            report["total_messages"] = value
            with self.subTest(messages=value):
                with self.assertRaisesRegex(ValueError, "verified echo traffic"):
                    self.validate(report)
        report = completed_report()
        report["peak_authenticated_connections"] = 63
        with self.assertRaisesRegex(ValueError, "concurrency was not reached"):
            self.validate(report)

    def test_rejects_missing_or_false_real_socket_cap_checks(self):
        for key in ("per_ip", "pending", "global"):
            for value in (False, None, 1):
                report = completed_report()
                report["limit_checks"][key] = value
                with self.subTest(key=key, value=value):
                    with self.assertRaisesRegex(ValueError, "admission-limit checks missing"):
                        self.validate(report)
            report = completed_report()
            del report["limit_checks"][key]
            with self.subTest(missing=key):
                with self.assertRaisesRegex(ValueError, "admission-limit checks missing"):
                    self.validate(report)

    def test_rejects_unreleased_admission_leases(self):
        for key, value in (("active", 1), ("pending", 1), ("admission_released", False)):
            report = completed_report()
            report[key] = value
            with self.subTest(key=key):
                with self.assertRaisesRegex(ValueError, "leases were not all released"):
                    self.validate(report)

    def test_rejects_live_or_unreported_native_keys(self):
        for kem in ({"live_keys": 1}, {}):
            report = completed_report()
            report["kem"] = kem
            with self.subTest(kem=kem):
                with self.assertRaisesRegex(ValueError, "KEM keys remain live"):
                    self.validate(report)

    def test_rejects_incomplete_authenticated_and_identity_closure(self):
        for key in ("authenticated_close_for_all_completed_pairs", "auth_key_closed"):
            report = completed_report()
            report[key] = False
            with self.subTest(key=key):
                with self.assertRaisesRegex(ValueError, "cleanup incomplete"):
                    self.validate(report)

    def test_rejects_pair_close_and_handshake_accounting_mismatches(self):
        for key, value in (
            ("authenticated_pairs_total", 63),
            ("authenticated_pair_closes", 191),
            ("successful_endpoint_handshakes", 383),
        ):
            report = completed_report()
            report[key] = value
            with self.subTest(key=key):
                with self.assertRaisesRegex(ValueError, "not all closed|accounting mismatch"):
                    self.validate(report)
        report = completed_report()
        report["kem"]["executed_jobs"] -= 1
        with self.assertRaisesRegex(ValueError, "accounting mismatch"):
            self.validate(report)

    def test_rejects_descriptor_leak_or_missing_resource_baseline(self):
        report = completed_report()
        report["final_resources"]["fd_count"] += 1
        with self.assertRaisesRegex(ValueError, "descriptor recovery"):
            self.validate(report)
        for key in ("resource_baseline", "final_resources"):
            report = completed_report()
            del report[key]["fd_count"]
            with self.subTest(key=key):
                with self.assertRaisesRegex(ValueError, "descriptor recovery"):
                    self.validate(report)

    def test_rejects_reported_execution_errors(self):
        report = completed_report()
        report["errors"] = ["fixture execution failed"]
        with self.assertRaisesRegex(ValueError, "execution errors"):
            self.validate(report)


class ResourceContracts(unittest.TestCase):
    def test_day_of_samples_retains_bounded_windows_and_exact_maxima(self):
        summary = collector.ResourceSummary()
        for second in range(86401):
            summary.add({'elapsed_seconds': second, 'rss_kib': second,
                         'peak_rss_kib': second + 10, 'fd_count': second % 100,
                         'threads': 5, 'cpu_seconds': second / 2})
        self.assertEqual(summary.count, 86401)
        self.assertEqual(len(summary.first_rss), 60)
        self.assertEqual(len(summary.tail_rss), 60)
        result = summary.report()
        self.assertEqual(result['rss_kib'], 86400)
        self.assertEqual(result['peak_rss_kib'], 86410)
        self.assertEqual(result['fd_count'], 99)
        self.assertEqual(result['warm_rss_median_kib'], 89.5)
        self.assertEqual(result['tail_rss_median_kib'], 86370.5)

    def test_limits_are_inclusive_and_one_unit_above_is_rejected(self):
        limits = {"rss_mib": 512, "fds": 256, "threads": 64}
        at_budget = {"peak_rss_kib": 512 * 1024, "fd_count": 256, "threads": 64}
        self.assertIsNone(collector.resource_violation(at_budget, limits))
        for key, message in (
            ("peak_rss_kib", "process RSS ceiling exceeded"),
            ("fd_count", "sampled descriptor ceiling exceeded"),
            ("threads", "sampled thread ceiling exceeded"),
        ):
            sample = dict(at_budget)
            sample[key] += 1
            with self.subTest(resource=key):
                self.assertEqual(collector.resource_violation(sample, limits), message)

    @unittest.skipUnless(sys.platform == "linux" and Path("/proc/self/status").exists(),
                         "Linux /proc is required")
    def test_current_process_sample_has_sane_resource_counters(self):
        sample = collector.sample_process(os.getpid())
        self.assertIsNotNone(sample)
        for key in ("rss_kib", "peak_rss_kib", "anonymous_rss_kib", "file_rss_kib",
                    "threads", "fd_count", "minor_faults", "major_faults"):
            with self.subTest(counter=key):
                self.assertIsInstance(sample[key], int)
                self.assertGreaterEqual(sample[key], 0)
        self.assertGreaterEqual(sample["threads"], 1)
        self.assertGreaterEqual(sample["fd_count"], 1)
        self.assertGreaterEqual(sample["peak_rss_kib"], sample["rss_kib"])
        self.assertTrue(math.isfinite(sample["cpu_seconds"]))
        self.assertGreaterEqual(sample["cpu_seconds"], 0)


class HourlyContracts(unittest.TestCase):
    def test_all_profiles_and_smoke_duration_are_supported(self):
        for name, seconds in collector.PROFILES.items():
            self.assertEqual(collector.duration_value(name), seconds)
        self.assertEqual(collector.duration_value('10s'), 10)

    def test_rejects_ambiguous_short_or_unbounded_duration(self):
        for value in ('0h', '9s', '25h', '1.5h', '1H', '-1h', '3600', '1h;date'):
            with self.subTest(value=value), self.assertRaises(collector.argparse.ArgumentTypeError):
                collector.duration_value(value)

    def test_watchdog_covers_every_reconnect_and_close_with_extra_epoch(self):
        self.assertEqual(collector.watchdog_budget(86400, 50), 100900)
        self.assertGreater(collector.watchdog_budget(86400, 1), 86400 * 2)
        self.assertLess(collector.watchdog_budget(86400, 1) + 3600, 7 * 86400)

    def test_rotation_disarms_echo_timer_but_has_a_fixed_deadline(self):
        watch = collector.ProgressWatch(0)
        watch.observe({'event': 'rotation_started'}, 1)
        for second in (6, 11, 16, 21, 26, 31):
            watch.observe({'event': 'rotation_progress'}, second)
            watch.check(second)
        with self.assertRaisesRegex(TimeoutError, 'rotation phase deadline'):
            watch.check(34)

    def test_echo_watchdog_rearms_after_reconnect_and_rejects_stall(self):
        watch = collector.ProgressWatch(0)
        watch.observe({'event': 'rotation_started'}, 1)
        watch.observe({'event': 'rotation_ready'}, 2)
        watch.observe({'event': 'traffic_started'}, 3)
        watch.observe({'event': 'sample', 'expected_established_connections': 64,
                       'total_messages': 100}, 4)
        watch.observe({'event': 'closing_started'}, 5)
        watch.check(16)
        watch.observe({'event': 'rotation_started'}, 16)
        watch.observe({'event': 'rotation_progress'}, 21)
        watch.observe({'event': 'rotation_progress'}, 26)
        watch.observe({'event': 'rotation_ready'}, 30)
        watch.observe({'event': 'traffic_started'}, 31)
        watch.check(45)
        watch.observe({'event': 'sample', 'expected_established_connections': 64,
                       'total_messages': 100}, 46)
        with self.assertRaisesRegex(TimeoutError, 'echo progress stalled'):
            watch.check(47)

    def test_closing_and_shutdown_cannot_disable_watchdogs_indefinitely(self):
        watch = collector.ProgressWatch(0)
        watch.observe({'event': 'rotation_started'}, 1)
        watch.observe({'event': 'rotation_ready'}, 2)
        watch.observe({'event': 'traffic_started'}, 3)
        watch.observe({'event': 'closing_started'}, 4)
        with self.assertRaisesRegex(TimeoutError, 'closing phase deadline'):
            watch.check(17)
        watch.observe({'event': 'sample', 'expected_established_connections': 0,
                       'total_messages': 100}, 15)
        watch.check(24)
        with self.assertRaisesRegex(TimeoutError, 'shutdown phase deadline'):
            watch.check(26)

    def test_echo_counter_is_monotonic_across_epochs(self):
        watch = collector.ProgressWatch(0)
        for start, count in ((1, 100), (10, 99)):
            watch.observe({'event': 'rotation_started'}, start)
            watch.observe({'event': 'rotation_ready'}, start + 1)
            watch.observe({'event': 'traffic_started'}, start + 2)
            event = {'event': 'sample', 'expected_established_connections': 64,
                     'total_messages': count}
            if count == 99:
                with self.assertRaisesRegex(ValueError, 'nonmonotonic'):
                    watch.observe(event, start + 3)
            else:
                watch.observe(event, start + 3)
                watch.observe({'event': 'closing_started'}, start + 4)

    def test_unbounded_rotation_heartbeat_without_setup_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'outside setup'):
            collector.ProgressWatch(0).observe({'event': 'rotation_progress'}, 1)

    def test_fixture_ca_leaf_and_pin_outlive_day_campaign_watchdog(self):
        from datetime import datetime, timezone
        from cryptography import x509
        from interop import identities
        budget = collector.watchdog_budget(86400, 1)
        lifetime = budget + 3600
        before = datetime.now(timezone.utc).timestamp()
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)
            _, pin = identities(path, lifetime_seconds=lifetime)
            for name in ('ca.pem', 'cert.pem'):
                cert = x509.load_pem_x509_certificate((path / name).read_bytes())
                self.assertGreater(cert.not_valid_after_utc.timestamp(), before + budget)
            self.assertGreater(pin['not_after'], before + budget)
            self.assertEqual((path / 'auth.bin').stat().st_mode & 0o777, 0o600)
            self.assertEqual((path / 'key.pem').stat().st_mode & 0o777, 0o600)

    def test_fixture_lifetime_rejects_invalid_or_excessive_values(self):
        from interop import identities
        for value in (True, 0, 59, 7 * 86400 + 1, 3600.0):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'fixture lifetime'):
                identities(None, lifetime_seconds=value)


if __name__ == "__main__":
    unittest.main()
