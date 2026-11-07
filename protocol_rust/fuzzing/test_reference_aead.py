"""Published RFC 8439 vectors and existing public Spiral fixture agreement."""
import json
from pathlib import Path
import unittest

from protocol_rust.fuzzing import reference_aead as aead


class PublishedVectors(unittest.TestCase):
    def test_rfc8439_section_2_3_2_chacha_block(self):
        expected = bytes.fromhex(
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
            "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e")
        self.assertEqual(aead.block(bytes(range(32)), bytes.fromhex(
            "000000090000004a00000000"), 1), expected)

    def test_rfc8439_section_2_5_2_poly1305(self):
        key = bytes.fromhex("85d6be7857556d337f4452fe42d506a8"
                            "0103808afb0db2fd4abff6af4149f51b")
        self.assertEqual(aead.poly1305(key, b"Cryptographic Forum Research Group"),
                         bytes.fromhex("a8061dc1305136c6c22b8baf0c0127a9"))

    def test_rfc8439_section_2_8_2_full_aead(self):
        key = bytes(range(0x80, 0xA0))
        nonce = bytes.fromhex("070000004041424344454647")
        aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
        plaintext = (b"Ladies and Gentlemen of the class of '99: If I could offer you only one "
                     b"tip for the future, sunscreen would be it.")
        payload = bytes.fromhex(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
            "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
            "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
            "3ff4def08e4b7a9de576d26586cec64b6116"
            "1ae10b594f09e26a7e902ecbd0600691")
        self.assertEqual(aead.encrypt(key, nonce, plaintext, aad), payload)
        self.assertEqual(aead.decrypt(key, nonce, payload, aad), plaintext)
        for value in (payload[:-1], payload + b"\0", payload[:-1] + bytes([payload[-1] ^ 1])):
            with self.assertRaises(ValueError):
                aead.decrypt(key, nonce, value, aad)
        with self.assertRaises(ValueError):
            aead.decrypt(key, nonce, payload, aad + b"\0")

    def test_existing_public_spiral_client_and_server_records(self):
        root = Path(__file__).resolve().parents[2]
        fixture = json.loads((root / "protocol_v01/tests/fixtures/test_vectors_v0.1.json").read_text())
        for role in ("client", "server"):
            key = bytes.fromhex(fixture["expected"][role + "_data_key"])
            prefix = bytes.fromhex(fixture["expected"][role + "_nonce_prefix"])
            for kind in ("data", "close"):
                name = role + "_" + kind
                raw = bytes.fromhex(fixture["frames"][name])
                plain = bytes.fromhex(fixture["plaintexts"][name])
                nonce = prefix + raw[28:36]
                self.assertEqual(aead.encrypt(key, nonce, plain, raw[:40]), raw[40:])
                self.assertEqual(aead.decrypt(key, nonce, raw[40:], raw[:40]), plain)


if __name__ == "__main__":
    unittest.main()
