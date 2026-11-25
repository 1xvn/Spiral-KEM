import json
from pathlib import Path
import tempfile
import unittest

from evidence import structured_result
from public_receipt import publish


class ReviewContracts(unittest.TestCase):
    def test_tls_observations_are_required(self):
        metadata = dict(schema='spiral-rust-adversarial/v0.3', tests=35, failures=0, errors=0)
        raw = (json.dumps(metadata) + '\n').encode()
        with self.assertRaises(ValueError):
            structured_result(raw, 35, None, raw, 'rust-tls')

    def test_publication_after_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'functional').mkdir()
            (root / 'functional/interop.json').write_text('PRIVATE-TEST-MARKER')
            public = root / 'public'
            publish('functional', 'failure', root, public)
            self.assertEqual([p.name for p in public.iterdir()], ['receipt.json'])
            self.assertNotIn('PRIVATE-TEST-MARKER', (public / 'receipt.json').read_text())
