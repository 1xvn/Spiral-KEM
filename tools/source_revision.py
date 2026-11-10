"""Resolve historical source aliases after the repository privacy rewrite.

The public map contains commit IDs only. Resolve before asking Git so locally
cached original objects cannot accidentally bypass the sanitized history.
"""
from __future__ import annotations

import json
from pathlib import Path
import re


def resolve_source_commit(repo, ref):
    """Map a legacy full ID or unique 7+ digit prefix, preserving Git suffixes.

    Branch names, unmapped IDs, and options pass through unchanged. Supported
    suffixes are ``^{commit}`` and ``:path`` (including their combination).
    Ambiguous prefixes and malformed maps raise ValueError before invoking Git.
    """
    if not isinstance(ref, str):
        raise TypeError("source revision must be a string")
    revision, separator, path = ref.partition(":")
    match = re.fullmatch(r"([a-fA-F0-9]{7,40})(\^\{commit\})?", revision)
    if match is None:
        return ref
    mapping_path = Path(repo) / "tools" / "source_commits.json"
    if not mapping_path.exists():
        return ref
    mapping = json.loads(mapping_path.read_text(encoding="utf-8"))
    if isinstance(mapping, dict) and "commits" in mapping:
        mapping = mapping["commits"]
    if not isinstance(mapping, dict) or any(
            not isinstance(old, str) or not isinstance(new, str)
            or re.fullmatch(r"[a-f0-9]{40}", old) is None
            or re.fullmatch(r"[a-f0-9]{40}", new) is None
            for old, new in mapping.items()):
        raise ValueError("invalid legacy source commit map")
    original = match[1].lower()
    matches = [old for old in mapping if old.startswith(original)]
    if len(matches) > 1:
        raise ValueError("ambiguous legacy source commit prefix: " + original)
    if not matches:
        return ref
    resolved = mapping[matches[0]] + (match[2] or "")
    return resolved + (separator + path if separator else "")
