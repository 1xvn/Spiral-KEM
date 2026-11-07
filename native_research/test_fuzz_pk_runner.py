"""Result gates must distinguish a real search from startup-only execution."""
import unittest

from native_research.fuzz_pk import feedback, passes


class ResultTests(unittest.TestCase):
    def test_real_engine_output_and_saturated_coverage(self):
        metrics = feedback('#10 INITED cov: 73 ft: 79\n#2000 DONE cov: 73 ft: 79\n'
                           'stat::number_of_executed_units: 2000\n')
        self.assertEqual(metrics, {'initialization_executed': 10, 'executed': 2000,
                                   'final_cov': 73, 'final_features': 79})
        self.assertTrue(passes(0, metrics))

    def test_failure_is_not_overridden_by_positive_feedback(self):
        metrics = feedback('#10 INITED cov: 73 ft: 79\nstat::number_of_executed_units: 2000\n')
        for code in (1, 77, -9, None):
            self.assertFalse(passes(code, metrics))

    def test_initialization_only_is_not_a_search(self):
        metrics = feedback('#202 INITED cov: 73 ft: 79\n#202 DONE cov: 73 ft: 79\n'
                           'stat::number_of_executed_units: 202\n')
        self.assertFalse(passes(0, metrics))

    def test_missing_zero_feedback_cannot_pass(self):
        complete = {'initialization_executed': 10, 'executed': 2000,
                    'final_cov': 73, 'final_features': 79}
        for key in complete:
            for value in (0, None):
                self.assertFalse(passes(0, {**complete, key: value}))
            self.assertFalse(passes(0, {k:v for k,v in complete.items() if k!=key}))
        self.assertFalse(passes(0, feedback('unrelated output')))


if __name__ == '__main__':
    unittest.main()
