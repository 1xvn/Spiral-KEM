"""Regression for the distributed source archive, which has no .git directory."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from protocol_rust.diagnostics.provenance import source_identity


class SourceIdentityTests(unittest.TestCase):
    def fixture(self,root):
        (root/'code.rs').write_bytes(b'public source fixture\n')
        manifest={'source_commit':'a'*40,'files':{'code.rs':hashlib.sha256((root/'code.rs').read_bytes()).hexdigest()}}
        (root/'SOURCE.json').write_text(json.dumps(manifest))
        return manifest

    def test_bundle_without_git_never_calls_git(self):
        with tempfile.TemporaryDirectory() as folder,patch('protocol_rust.diagnostics.provenance.subprocess.check_output',side_effect=AssertionError('Git must not be used')):
            root=Path(folder);self.fixture(root)
            result=source_identity(root)
            self.assertEqual(result['source_identity_kind'],'bundle_manifest')
            self.assertEqual(result['source_commit'],'a'*40)
            self.assertEqual(result['bundle_verified_files'],1)
            self.assertNotIn('git_commit',result)

    def test_changed_empty_or_escaping_manifest_is_rejected_without_git_fallback(self):
        for change in ('modified','missing','empty','escape','commit'):
            with self.subTest(change=change),tempfile.TemporaryDirectory() as folder,patch('protocol_rust.diagnostics.provenance.subprocess.check_output',side_effect=AssertionError('no Git fallback')):
                root=Path(folder);manifest=self.fixture(root)
                if change=='modified':(root/'code.rs').write_text('different source')
                if change=='missing':(root/'code.rs').unlink()
                if change=='empty':manifest['files']={}
                if change=='escape':manifest['files']={'../code.rs':'0'*64}
                if change=='commit':manifest['source_commit']='not a commit'
                (root/'SOURCE.json').write_text(json.dumps(manifest))
                with self.assertRaises(ValueError):source_identity(root)

    def test_git_checkout_requires_own_root_and_records_git_identity(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            with patch('protocol_rust.diagnostics.provenance.subprocess.check_output',side_effect=[str(root)+'\n','b'*40+'\n']):
                result=source_identity(root)
                self.assertEqual(result['git_commit'],'b'*40)
            with patch('protocol_rust.diagnostics.provenance.subprocess.check_output',return_value=str(root.parent)+'\n'):
                with self.assertRaisesRegex(ValueError,'root differs'):source_identity(root)


if __name__=='__main__':unittest.main()
