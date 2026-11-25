"""Strict transcript readers for the pinned unittest and libtest formats."""
from collections import defaultdict
from functools import lru_cache
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


@lru_cache
def contract(name):
    return strict_json(Path(__file__).with_name(name + '.json').read_bytes())


def exact(actual, expected, message):
    # Python equality would equate false to 0 and true to 1.
    require(json.dumps(actual, sort_keys=True) == json.dumps(expected, sort_keys=True), message)


def unittest_result(raw, expected, *, suite=None):
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
    if suite is not None:
        exact(sorted(identities), contract("test_inventory")[suite], "unexpected unittest inventory")
    return sorted(identities)


def libtest_result(raw, expected, ignored=0, filtered=None, *, inventory=None):
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
    if inventory is not None:
        exact(cases, inventory, "unexpected libtest identities or statuses")
    return dict(zip(("passed", "failed", "ignored", "measured", "filtered_out"), counts))




def libtest_groups(raw, expected, inventories=None):
    rows = lines(raw)
    boundaries = [i for i, row in enumerate(rows) if re.fullmatch(r"running \d+ tests?", row)]
    require(bool(boundaries) and len(boundaries) == len(expected) and boundaries[0] == 0, "missing or extra libtest groups")
    return [libtest_result(("\n".join(rows[start:end]) + "\n").encode(), count, filtered=0,
                           inventory=inventories[i] if inventories is not None else None)
            for i, (start, end, count) in enumerate(zip(boundaries, boundaries[1:]+[len(rows)], expected))]

def client_auth_rejections(data):
    cases = data.get("cases", [])
    expected_cases = contract("client_auth_contract")
    configs = data["configuration"]
    config_names = {"missing-registry", "unknown-role", "duplicate", "invalid-digest"}
    require(len(configs) == 4 and {r["case"] for r in configs} == config_names,
            "missing configuration denial")
    for row in configs:
        exact(row, {"case": row["case"], "server_exit": 1, "server_report": {
            "status": "failed", "kem": {"executed_jobs": 0, "live_keys": 0, "rejected_jobs": 0}}},
            "invalid configuration denial")
    require(len(cases) == len(expected_cases) and {case["case"] for case in cases} == set(expected_cases),
            "missing or duplicate client-auth cases")
    rejections = []
    for case in cases:
        name = case["case"]
        rows = case["server_stdout_after_listen"]
        final = rows[-1]
        spec = expected_cases[name]
        stages = [{"event": event} for event in spec["events"]]
        if name not in ("read-status", "required-to-legacy"):
            stages.append({"event": "failure_cleanup", "role": "server", "active": 0,
                           "pending": 0, "auth_key_closed": True, "drained": True})
        exact(rows[:-1], stages, "wrong authorization stage or cleanup")
        exact(final["kem"], {"executed_jobs": spec["jobs"], "live_keys": 0, "rejected_jobs": 0},
              "wrong authorization KEM accounting")
        require(type(case["server_exit"]) is int, "invalid server exit")
        if name == "read-status":
            require(case["decision"] == "allow" and case["server_exit"] == 0
                    and case["server_stderr"] == "" and final["status"] == "passed"
                    and final["auth_key_closed"] is final["admission_released"] is True,
                    "client-auth success lacks cleanup")
            exact(final["sessions"], [{"messages": 1, "authenticated_close": True}], "missing status read")
            continue
        expected = {"missing-spiral-server-pin": "Transport",
                    "other-session-record": "Closed", "duplicate-record": "Closed"}.get(name, "Authentication")
        require(case["decision"] == "deny" and case["server_exit"] == 1
                and case["server_stderr"] == f"Error: {expected}\n" and final["status"] == "failed"
                and final["kem"]["live_keys"] == final["kem"]["rejected_jobs"] == 0,
                "client-auth rejection lacks its expected reason or KEM cleanup")
        rejections.append({"case": name, "classification": "expected_rejection", "reason": expected})
    require(len(rejections) == 19, "missing successful client-auth control")
    return rejections


def tls_observations(data):
    specs = contract("tls_contract")
    by_case = defaultdict(list)
    for row in data["observations"]:
        by_case[row["scenario"]].append(row)
    require(by_case.keys() == specs.keys(), "missing or extra TLS scenario")
    seen_sessions = set()
    for name, expected in specs.items():
        rows = by_case[name]
        require(len(rows) == len(expected), "missing TLS endpoint or repetition")
        for row, spec in zip(rows, expected):
            report = row["report"]
            role, reason = spec["role"], spec["reason"]
            exact(row["variant"], spec["variant"], "wrong TLS repetition")
            require(row["role"] == role and type(row["exit"]) is int and
                    row["exit"] == (1 if reason else 0) and
                    row["reason"] == (f"Error: {reason}\n" if reason else "") and
                    report["status"] == ("failed" if reason else "passed"), "wrong TLS outcome")
            exact(report["kem"], {"live_keys": 0, "rejected_jobs": 0, "executed_jobs": spec["jobs"]},
                  "wrong TLS KEM accounting")
            if reason:
                continue
            require(report["role"] == role and report["connections"] == len(spec["messages"]),
                    "wrong TLS endpoint session count")
            if role == "server":
                require(report["auth_key_closed"] is report["admission_released"] is True,
                        "TLS server did not release ownership")
            sessions = report["sessions"]
            exact([item["messages"] for item in sessions], spec["messages"], "missing TLS messages")
            for item in sessions:
                sid = item["session_id"]
                require(item["authenticated_close"] is True and re.fullmatch("[0-9a-f]{32}", sid)
                        and (role, sid) not in seen_sessions, "duplicate or unclosed TLS session")
                seen_sessions.add((role, sid))
                if role == "client" and "payload" in spec["variant"]:
                    exact(item["payload_bytes"], spec["variant"]["payload"], "wrong TLS payload")


def structured_result(raw, expected, binary_hash, stdout, name):
    data = strict_json(raw)
    require(type(data) is dict, "expected structured result object")
    for field, value in (("tests", expected), ("failures", 0), ("errors", 0), ("skipped", 0)):
        actual = data.get(field, 0 if field == "skipped" and name in ("rust-tls", "client-auth-lab") else None)
        require(type(actual) is int and actual == value, "structured " + field + " mismatch")
    result = {"tests": expected, "failures": 0, "errors": 0}
    if name == "client-auth-lab":
        require(stdout == b"", "unexpected client-auth stdout")
        require(data.get("schema") == 1 and data.get("passed") is True, "client-auth summary failed")
        result["expected_rejections"] = client_auth_rejections(data)
    elif name == "rust-tls":
        require(data.get("schema") == "spiral-rust-adversarial/v0.4", "unexpected TLS schema")
        tls_observations(data)
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


def scratch_result(folder, stdout, stderr):
    from_matrix = contract("test_inventory")
    labels = [line.decode() for line in stdout.splitlines()[:-1]]
    required = {key.split("/", 1)[1] for key in from_matrix if key.startswith("scratch/")}
    require(not stderr and stdout.endswith(b"\n") and len(labels) == len(required) and
            set(labels) == required, "incomplete scratch matrix stdout")
    summary = strict_json(stdout.splitlines()[-1])
    exact(summary, {"status": "passed", "tests": 23, "output": str(folder)}, "wrong scratch summary")
    data = strict_json((folder / "result.json").read_bytes())
    require(data["schema"] == "spiral-scratch-cleanup-validation/v1" and
            data["status"] == "passed" and data["source_unchanged"] is True and
            data["tests"] == 23 and [c["name"] for c in data["checks"]] == labels,
            "incomplete scratch child receipt")
    total = 0
    for row in data["checks"]:
        name = row["name"]
        require(row["passed"] is True and type(row["exit"]) is int and row["exit"] == 0
                and not row.get("timed_out"), "scratch child incomplete")
        streams = {}
        for stream in ("stdout", "stderr"):
            filename = name + "." + stream
            raw = (folder / filename).read_bytes()
            exact(row[stream], {"file": filename, "sha256": sha(raw)}, "scratch stream mismatch")
            streams[stream] = raw
        require(not re.search(rb"(?m)^(?:error(?:\[[^\]]+\])?:|test result: FAILED|failures:)",
                              streams["stderr"]), "scratch tool error")
        inventories = from_matrix["scratch/" + name]
        counts = [len(group) for group in inventories]
        exact(row["expected_group_counts"], counts, "wrong scratch selection")
        groups = libtest_groups(streams["stdout"], counts, inventories)
        exact(row["test_groups"], groups, "scratch child summary mismatch")
        total += sum(g["passed"] for g in groups)
    require(total == 23, "incomplete scratch matrix")
