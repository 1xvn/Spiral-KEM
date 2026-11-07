"""Evidence gates, strict replay equality, and archive integrity checks."""
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from protocol_rust.fuzzing.campaign import (
    build_environment, bundle, clean_exit, decode_row, matches_reference, parse_feedback,
    search_completed, write_report,
)
from protocol_rust.fuzzing.rustc_wrapper import instrument_args


class Gates(unittest.TestCase):
    def test_initialization_only_zero_feedback_and_crashes_cannot_pass(self):
        good = '#43 INITED cov: 5 ft: 9\n#2000 DONE cov: 5 ft: 9\nstat::number_of_executed_units: 2000\n'
        metrics = parse_feedback(good)
        self.assertTrue(search_completed(0, good, metrics))
        self.assertFalse(search_completed(77, good, metrics))
        self.assertFalse(search_completed(0, good, {**metrics,'executed':43}))
        for key in ('initialization_executed','executed','final_cov','final_features'):
            self.assertFalse(search_completed(0,good,{**metrics,key:0}))
            self.assertFalse(search_completed(0,good,{k:v for k,v in metrics.items() if k!=key}))

    def test_diagnostics_fail_even_when_process_returns_zero(self):
        for text in ('ERROR: AddressSanitizer: heap-buffer-overflow',
                     'SUMMARY: LeakSanitizer: detected memory leaks',
                     'LeakSanitizer has encountered a fatal error',
                     "thread 'main' panicked at parser.rs:4:5", 'runtime error: bad alignment'):
            self.assertFalse(clean_exit(0,text))
        self.assertTrue(clean_exit(0,'Done 2000 runs'))

    def test_replay_rejects_swapped_paths_wrong_types_and_extra_fields(self):
        path = Path('/run/corpus/input')
        expected = {'accepted':True,'kind':1}
        good = {'file':str(path),'result':expected}
        self.assertTrue(matches_reference(good,path,expected))
        for bad in ({},[],{**good,'file':'other'},
                    {**good,'result':{'accepted':1,'kind':1}},
                    {**good,'result':{'accepted':True,'kind':True}},
                    {**good,'result':{'accepted':True,'kind':1.0}},
                    {**good,'extra':0}):
            self.assertFalse(matches_reference(bad,path,expected))

    def test_replay_json_rejects_duplicate_fields_and_nonfinite_numbers(self):
        self.assertEqual(decode_row('{"file":"a","result":{"accepted":false}}'),
                         {'file':'a','result':{'accepted':False}})
        for text in ('{"file":"wrong","file":"right","result":{}}',
                     '{"result":{"accepted":false,"accepted":true}}',
                     '{"result":NaN}','{"result":Infinity}','{"result":-Infinity}'):
            with self.assertRaises(ValueError):
                decode_row(text)

    def test_controlled_build_and_sanitizer_options_override_inherited_flags(self):
        with patch.dict(os.environ,{'CARGO_ENCODED_RUSTFLAGS':'unwanted',
            'RUSTC_WORKSPACE_WRAPPER':'unwanted','CXXFLAGS':'-fsanitize=fuzzer',
            'HOST_CFLAGS':'bad','CUSTOM_LIBFUZZER_PATH':'bad',
            'ASAN_OPTIONS':'detect_leaks=0','LSAN_OPTIONS':'exitcode=0:suppressions=bad'}):
            env = build_environment(Path('/toolchain'),Path('/trace'))
        for key in ('CARGO_ENCODED_RUSTFLAGS','RUSTC_WORKSPACE_WRAPPER','CXXFLAGS','HOST_CFLAGS','CUSTOM_LIBFUZZER_PATH'):
            self.assertNotIn(key,env)
        self.assertIn('detect_leaks=1',env['ASAN_OPTIONS'])
        self.assertEqual(env['LSAN_OPTIONS'],'exitcode=23')
        self.assertEqual(env['CARGO_PROFILE_RELEASE_LTO'],'false')


class CompilerBoundary(unittest.TestCase):
    def test_only_exact_production_library_receives_feedback(self):
        args = ['--crate-name','spiral_protocol','--crate-type','lib','--emit=dep-info,metadata,link']
        actual, info = instrument_args(args)
        self.assertTrue(info['coverage_enabled'])
        self.assertIn('-Cpasses=sancov-module',actual)
        self.assertIn('--emit=dep-info,metadata,link,llvm-ir',actual)
        for name in ('frame_target','hello_target','replay_target','spiral_protocol_helper','build_script_build'):
            actual, info = instrument_args(['--crate-name='+name,'--crate-type=bin','--emit=link'])
            self.assertFalse(info['coverage_enabled'])
            self.assertFalse(any('sanitizer-coverage' in flag or 'sancov-module' in flag for flag in actual))
        _, info = instrument_args(['--crate-name','spiral_protocol','--crate-type','bin'])
        self.assertFalse(info['coverage_enabled'])

    def test_queries_and_ambiguous_crate_names_are_not_instrumented(self):
        args = ['--crate-name=spiral_protocol','--crate-type=lib','--print=cfg']
        _, info = instrument_args(args)
        self.assertTrue(info['is_query'])
        self.assertFalse(info['coverage_enabled'])
        _, info = instrument_args(['--crate-name=a','--crate-name=spiral_protocol','--crate-type=lib'])
        self.assertFalse(info['coverage_enabled'])
        with self.assertRaises(ValueError):
            instrument_args(['--crate-name'])


class Packaging(unittest.TestCase):
    def test_complete_archive_excludes_build_and_preserves_existing_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); out = root/'run'; out.mkdir(); (out/'build').mkdir()
            (out/'build/binary').write_bytes(b'not for upload')
            (out/'engine.log').write_text('raw log\n')
            write_report(out,{'status':'failed','error':'example'})
            write_report(out,{'status':'failed','error':'updated example'})
            manifest = json.loads((out/'SHA256.json').read_text())
            self.assertNotIn('SHA256.json',manifest)
            self.assertNotIn('build/binary',manifest)
            destination = root/'run.tar.gz'; bundle(out,destination)
            with tarfile.open(destination,'r:gz') as archive:
                names = archive.getnames()
                self.assertIn('run/result.json',names)
                self.assertIn('run/engine.log',names)
                self.assertFalse(any('/build' in name for name in names))
            before = destination.read_bytes()
            with self.assertRaises(FileExistsError):
                bundle(out,destination)
            self.assertEqual(before,destination.read_bytes())

    def test_missing_result_and_unsafe_entries_never_publish_partial_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); out = root/'run'; out.mkdir(); archive = root/'run.tar.gz'
            with self.assertRaises(RuntimeError):
                bundle(out,archive)
            write_report(out,{'status':'failed'})
            (out/'linked').symlink_to(out/'result.json')
            with self.assertRaises(RuntimeError):
                bundle(out,archive)
            self.assertFalse(archive.exists())
            self.assertFalse(list(root.glob('*.partial')))


if __name__ == '__main__':
    unittest.main()
