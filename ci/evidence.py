"""Strict transcript readers for the pinned unittest and libtest formats."""
import hashlib
import json
import math
import os
from pathlib import Path
import re
import tempfile


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def strict_json(raw):
    def unique(fields):
        result = dict(fields)
        require(len(result) == len(fields), "duplicate JSON field")
        return result

    def invalid(value):
        raise ValueError("non-finite JSON value: " + value)

    def floating(value):
        result = float(value)
        require(math.isfinite(result), "non-finite JSON number")
        return result

    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid, parse_float=floating)


def fresh_result(path):
    require(not path.exists() and not path.is_symlink(), "stale structured result")


def completed(record):
    require(type(record.get("exit")) is int and record["exit"] == 0
            and not record.get("timeout") and not record.get("execution_error"),
            "command failed or did not complete")


def matching_hash(expected, actual, label):
    require(expected == actual, label + " hash mismatch")


def atomic_json(path, data):
    # Readers either see the complete prior record or the complete replacement.
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as stream:
        temp = Path(stream.name)
        try:
            json.dump(data, stream, indent=2)
            stream.write("\n")
            stream.close()
            os.replace(temp, path)
        finally:
            temp.unlink(missing_ok=True)


def lines(raw):
    require(not raw or raw.endswith(b"\n"), "truncated transcript")
    return [line for line in raw.decode("utf-8").splitlines() if line.strip()]


def unittest_result(raw, expected):
    rows = lines(raw)
    require(len(rows) >= 4 and rows[-1] == "OK" and rows[-3] == "-" * 70,
            "missing terminal unittest success")
    summary = re.fullmatch(r"Ran (\d+) tests? in \d+(?:\.\d+)?s", rows[-2])
    require(summary is not None, "invalid unittest summary")
    identities = set()
    for row in rows[:-3]:
        case = re.fullmatch(r"(test\w*) \(([\w.]+)\) \.\.\. ok", row)
        require(case is not None, "unexpected unittest record")
        identity = case[2]
        require(identity.rsplit(".", 1)[-1] == case[1], "inconsistent unittest identity")
        require(identity not in identities, "duplicate unittest identity")
        identities.add(identity)
    require(int(summary[1]) == len(identities) == expected and expected > 0,
            "unittest rows or count differ from expected suite")
    return sorted(identities)


def libtest_result(raw, expected, ignored=0, filtered=None):
    rows = lines(raw)
    require(len(rows) >= 3, "missing libtest group")
    started = re.fullmatch(r"running (\d+) tests?", rows[0])
    summary = re.fullmatch(
        r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; "
        r"(\d+) measured; (\d+) filtered out; finished in \d+(?:\.\d+)?s", rows[-1])
    require(started is not None and summary is not None, "missing terminal libtest success")
    counts = list(map(int, summary.groups()))
    require(counts[:4] == [expected, 0, ignored, 0] and expected > 0
            and (filtered is None or counts[4] == filtered), "unexpected libtest counts")
    cases = {}
    for row in rows[1:-1]:
        case = re.fullmatch(r"test (.+) \.\.\. (ok|ignored(?:, .+)?)", row)
        require(case is not None, "unexpected libtest record")
        require(case[1] not in cases, "duplicate libtest identity")
        cases[case[1]] = case[2].split(",")[0]
    require(int(started[1]) == len(cases) == expected + ignored
            and list(cases.values()).count("ok") == expected,
            "libtest rows do not agree with counts")
    return dict(zip(("passed", "failed", "ignored", "measured", "filtered_out"), counts))




def libtest_groups(raw, expected):
    rows = lines(raw)
    boundaries = [i for i, row in enumerate(rows) if re.fullmatch(r"running \d+ tests?", row)]
    require(bool(boundaries) and len(boundaries) == len(expected) and boundaries[0] == 0, "missing or extra libtest groups")
    return [libtest_result(("\n".join(rows[start:end]) + "\n").encode(), count, filtered=0)
            for start, end, count in zip(boundaries, boundaries[1:]+[len(rows)], expected)]

def client_auth_rejections(data):
    cases = data.get("cases", [])
    expected_cases = {
        "read-status", "missing-certificate", "untrusted-issuer", "expired",
        "server-only-certificate", "dual-purpose-certificate", "wrong-sni", "legacy-to-required",
        "unregistered", "revoked-on-restart", "grant-for-other-server", "grant-for-other-service",
        "forbidden-write", "forbidden-resource", "self-declared-role", "wrong-handshake-service",
        "missing-spiral-server-pin", "other-session-record", "duplicate-record", "required-to-legacy",
    }
    require(len(cases) == len(expected_cases) and {case["case"] for case in cases} == expected_cases,
            "missing or duplicate client-auth cases")
    rejections = []
    for case in cases:
        name = case["case"]
        rows = case["server_stdout_after_listen"]
        final = rows[-1]
        if name == "read-status":
            require(case["decision"] == "allow" and case["server_exit"] == 0
                    and case["server_stderr"] == "" and final["status"] == "passed"
                    and final["auth_key_closed"] is final["admission_released"] is True,
                    "client-auth success lacks cleanup")
            continue
        expected = {"missing-spiral-server-pin": "Transport",
                    "other-session-record": "Closed", "duplicate-record": "Closed"}.get(name, "Authentication")
        require(case["decision"] == "deny" and case["server_exit"] == 1
                and case["server_stderr"] == f"Error: {expected}\n" and final["status"] == "failed"
                and final["kem"]["live_keys"] == final["kem"]["rejected_jobs"] == 0,
                "client-auth rejection lacks its expected reason or KEM cleanup")
        if name != "required-to-legacy":
            require(len(rows) >= 3 and rows[-2] ==
                    {"event": "failure_cleanup", "role": "server", "active": 0, "pending": 0,
                     "auth_key_closed": True, "drained": True}, "client-auth rejection lacks cleanup")
        rejections.append({"case": name, "classification": "expected_rejection", "reason": expected})
    require(len(rejections) == 19, "missing successful client-auth control")
    return rejections


def structured_result(raw, expected, binary_hash, stdout, name):
    data = strict_json(raw)
    require(type(data) is dict, "expected structured result object")
    for field, value in (("tests", expected), ("failures", 0), ("errors", 0), ("skipped", 0)):
        actual = data.get(field, 0 if field == "skipped" and name in ("rust-tls", "client-auth-lab") else None)
        require(type(actual) is int and actual == value, "structured " + field + " mismatch")
    result = {"tests": expected, "failures": 0, "errors": 0}
    if name == "client-auth-lab":
        require(data.get("schema") == 1 and data.get("passed") is True, "client-auth summary failed")
        result["expected_rejections"] = client_auth_rejections(data)
    elif name == "rust-tls":
        require(data.get("schema") == "spiral-rust-adversarial/v0.3", "unexpected TLS schema")
    else:
        require(data.get("status") == "passed" and data.get("source_and_binary_unchanged") is True,
                "key operation summary failed")
        require(data.get("binary_sha256") == binary_hash, "nested binary hash mismatch")
        for field in ("binary_sha256_before", "binary_sha256_after"):
            if field in data:
                require(data[field] == binary_hash, "nested binary hash mismatch")
    if name != "client-auth-lab":
        published = lines(stdout)
        require(len(published) == 1 and strict_json(published[0]) ==
                {k: v for k, v in data.items() if k != "observations" or name != "rust-tls"},
                "stdout and structured result differ")
    return result
