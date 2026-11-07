"""Public-fixture ciphertext oracle for the experimental native implementation.

Corpus generation and header rendering use only the Python standard library.
The pinned OPT2 implementation is loaded lazily when Reference is constructed;
neither this module nor its generated header contains a service secret.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_SOURCE = ROOT / "protocol_v01/tests/fixtures/test_vectors_v0.1.json"
REFERENCE_SOURCE = ROOT / "code/opt2/spiral_kem_toy_v031_opt2.py"
REFERENCE_SHA256 = "74c1ff02669d5b6eea87ccf650bc6930bc1822ffe8568fa68ce79fb29958a118"
PREFIX = b"SKW1C\x06\x00\x00"
CT_BYTES = 1160
Q = 3329
_REFERENCE_NAME = "_spiral_native_ct_oracle_verified_" + REFERENCE_SHA256


def fixture() -> dict[str, bytes]:
    """Read the existing public KAT, including its three ordered keygen seeds."""
    vector = json.loads(FIXTURE_SOURCE.read_text(encoding="utf-8"))
    seeds = vector["inputs"]["kem_test_seeds"]
    result = {
        "seeds": b"".join(bytes.fromhex(seeds[name])
                          for name in ("matrix", "secret", "fallback")),
        "pk": bytes.fromhex(vector["public"]["kem_public_key_skw1"]),
        "ct": bytes.fromhex(vector["public"]["kem_ciphertext_skw1"]),
        "ss": bytes.fromhex(vector["expected"]["shared_secret"]),
        "message": bytes.fromhex(seeds["message"]),
    }
    lengths = {"seeds": 96, "pk": 808, "ct": CT_BYTES, "ss": 32, "message": 32}
    if any(len(result[name]) != size for name, size in lengths.items()):
        raise ValueError("public KAT has unexpected field lengths")
    return result


def canonical(data: bytes) -> bool:
    """Check baseline SKW1 CT framing and all 768 unsigned 12-bit coefficients.

    Exact bytes are required, matching the pinned Python wire parser. This check
    does not use that parser or determine whether re-encryption will succeed.
    """
    if type(data) is not bytes or len(data) != CT_BYTES or data[:8] != PREFIX:
        return False
    for offset in range(8, CT_BYTES, 3):
        pair = int.from_bytes(data[offset:offset + 3], "little")
        if (pair & 0xFFF) >= Q or (pair >> 12) >= Q:
            return False
    return True


def _with_coefficient(data: bytes, index: int, value: int) -> bytes:
    """Replace one packed coefficient without changing its paired neighbor."""
    changed = bytearray(data)
    offset = 8 + 3 * (index // 2)
    shift = 12 * (index % 2)
    pair = int.from_bytes(changed[offset:offset + 3], "little")
    pair = (pair & ~(0xFFF << shift)) | (value << shift)
    changed[offset:offset + 3] = pair.to_bytes(3, "little")
    return bytes(changed)


def seed_inputs() -> list[bytes]:
    """Return deterministic, unique raw inputs with a maximum length of 1280."""
    golden = fixture()["ct"]
    inputs = [golden, b""]
    inputs.extend(golden[:length] for length in (0, 1, 7, 8, 1159))
    inputs.extend((golden + b"\x00", golden + bytes(1280 - CT_BYTES)))
    for offset in range(len(PREFIX)):
        changed = bytearray(golden)
        changed[offset] ^= 1
        inputs.append(bytes(changed))
    # Both halves of each initial pair cover the shared middle-byte nibbles.
    for index in (0, 1, 256, 257, 512, 513):
        for value in (0, 1, 3328, 3329, 4095):
            inputs.append(_with_coefficient(golden, index, value))
    # Preserve wire canonicality while exercising distinct u/v and end positions.
    # Their validity is determined by reference decapsulation, never by position.
    for index in (0, 255, 256, 511, 512, 767):
        offset = 8 + 3 * (index // 2)
        pair = int.from_bytes(golden[offset:offset + 3], "little")
        old = (pair >> (12 * (index % 2))) & 0xFFF
        inputs.append(_with_coefficient(golden, index, (old + 1) % Q))
    return list(dict.fromkeys(inputs))


def render_header() -> str:
    """Render only public fixture arrays needed by the native test harness."""
    vector = fixture()
    lines = [
        "/* Generated from the public protocol v0.1 KAT; test data only. */",
        "#ifndef SPIRAL_CT_FIXTURE_H",
        "#define SPIRAL_CT_FIXTURE_H",
        "#include <stdint.h>",
        "",
    ]
    for name in ("seeds", "pk", "ct", "ss"):
        data = vector[name]
        lines.append(f"static const uint8_t FIXTURE_{name.upper()}[{len(data)}] = {{")
        for offset in range(0, len(data), 12):
            lines.append("    " + ", ".join(f"0x{byte:02x}" for byte in data[offset:offset + 12]) + ",")
        lines.extend(("};", ""))
    lines.append("#endif /* SPIRAL_CT_FIXTURE_H */")
    return "\n".join(lines) + "\n"


def _load_reference():
    """Execute the exact pinned source bytes without importing protocol TLS code."""
    data = REFERENCE_SOURCE.read_bytes()
    if hashlib.sha256(data).hexdigest() != REFERENCE_SHA256:
        raise RuntimeError("OPT2 reference source hash differs from pinned profile")
    module = sys.modules.get(_REFERENCE_NAME)
    if module is None:
        spec = importlib.util.spec_from_file_location(_REFERENCE_NAME, REFERENCE_SOURCE)
        if spec is None or spec.loader is None:
            raise RuntimeError("OPT2 reference source cannot be loaded")
        module = importlib.util.module_from_spec(spec)
        # Dataclasses resolve annotations through the module registry.
        sys.modules[_REFERENCE_NAME] = module
        try:
            exec(compile(data, str(REFERENCE_SOURCE), "exec"), module.__dict__)
        except BaseException:
            sys.modules.pop(_REFERENCE_NAME, None)
            raise
    return module


class Reference:
    """Reusable OPT2 reference key derived exclusively from the public KAT.

    The pinned key records are frozen dataclasses holding immutable tuples and
    bytes. Decapsulation reads them and constructs fresh intermediates, so this
    reference can retain its key while the native harness consumes a fresh key
    for every candidate.
    """

    def __init__(self) -> None:
        vector = fixture()
        self.module = _load_reference()
        self.kem = self.module.SpiralKEM()
        keygen_seeds = [vector["seeds"][offset:offset + 32] for offset in (0, 32, 64)]
        with patch.object(self.module.secrets, "token_bytes", side_effect=keygen_seeds):
            self.pk, self.sk = self.kem.keygen()
        if self.kem.serialize_public_key_compact(self.pk) != vector["pk"]:
            raise RuntimeError("OPT2 reference public key differs from public KAT")
        with patch.object(self.module.secrets, "token_bytes", return_value=vector["message"]):
            ciphertext, shared = self.kem.encapsulate(self.pk)
        if (self.kem.serialize_ciphertext_compact(ciphertext) != vector["ct"]
                or shared != vector["ss"]):
            raise RuntimeError("OPT2 reference encapsulation differs from public KAT")
        if self.kem.decapsulate(self.sk, ciphertext) != vector["ss"]:
            raise RuntimeError("OPT2 reference decapsulation differs from public KAT")

    def expected(self, data: bytes) -> dict[str, int | bytes]:
        """Return native parsing status and the reference's 32-byte output.

        Every input reaches the pinned parser, whose framing decision must agree
        with the independent canonicality check. Disagreement raises an error.
        Canonical ciphertexts always have API status zero. Their secret is the
        actual reference result, including implicit rejection when applicable.
        """
        try:
            ciphertext = self.kem.deserialize_ciphertext_compact(data)
        except self.module.InputValidationError as error:
            if canonical(data):
                raise AssertionError("pinned parser rejected a canonical ciphertext") from error
            return {"status": 1, "ss": bytes(32)}
        if not canonical(data):
            raise AssertionError("pinned parser accepted a noncanonical ciphertext")
        return {"status": 0, "ss": self.kem.decapsulate(self.sk, ciphertext)}
