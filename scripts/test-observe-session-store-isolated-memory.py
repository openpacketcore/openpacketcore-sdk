"""Negative controls for measurement scope, units and process identity."""

import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "isolated_memory_observer", Path(__file__).with_name("observe-session-store-isolated-memory.py"))
OBSERVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OBSERVER)


class MemoryObservationTests(unittest.TestCase):
    def test_units_and_missing_or_duplicate_samples_fail_closed(self):
        self.assertEqual(OBSERVER.kib("Rss: 2048 kB\nPss: 1234 kB\n", "Rss"), 2048)
        for raw in ["Rss: 1 MB", "Rss: -1 kB", "Rss: 1 kB\nRss: 2 kB", "Pss: 1 kB", "Rss: 1"]:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                OBSERVER.kib(raw, "Rss")

    def test_reused_pid_is_not_a_sample_from_the_original_process(self):
        pid = os.getpid()
        identity = OBSERVER.process_identity(pid)
        sample = OBSERVER.memory_sample(pid, identity)
        self.assertGreater(sample["smaps_pss_kib"], 0)
        self.assertGreaterEqual(sample["smaps_rss_kib"], sample["smaps_pss_kib"])
        with self.assertRaises(ValueError):
            OBSERVER.memory_sample(pid, identity + 1)

    def test_successful_command_without_a_measured_voter_is_incomplete(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = OBSERVER.observe([sys.executable, "-c", "pass"], os.environ.copy(),
                                      Path(temporary), 0)
        self.assertEqual(result["exit_code"], 0)
        self.assertFalse(result["measurement_complete"])
        self.assertIsNone(result["maximum_observed_smaps_rss_kib"])
        self.assertFalse(result["deployment_memory_qualified"])

    def test_complete_cold_measurement_retains_maximum_and_never_qualifies_deployment(self):
        # These synthetic stage values test aggregation; they are not measurements.
        program = """
import json, os, time
stages = ['baseline', 'original_install_complete', 'generation_written',
          'catalog_admitted', 'cold_image_retained', 'native_roots_released']
for index, stage in enumerate(stages):
    print('isolated_voter_stage=' + json.dumps(dict(
        stage=stage, voter=0, voter_instances=1, pid=os.getpid(),
        smaps_rss_kib=4_000_000-index, smaps_pss_kib=3_000_000-index,
        vmhwm_estimate_kib=5_000_000-index, deployment_memory_qualified=False)), flush=True)
    time.sleep(0.3)
"""
        with tempfile.TemporaryDirectory() as temporary:
            result = OBSERVER.observe([sys.executable, "-c", program], os.environ.copy(),
                                      Path(temporary), 0)
        self.assertTrue(result["measurement_complete"], result["errors"])
        self.assertEqual(result["maximum_observed_smaps_rss_kib"], 4_000_000)
        self.assertEqual(result["maximum_observed_vmhwm_estimate_kib"], 5_000_000)
        self.assertFalse(result["deployment_memory_qualified"])
        self.assertTrue(result["transient_peaks_may_be_missed"])

    def test_another_voters_marker_cannot_complete_the_measurement(self):
        program = """
import json, os
print('isolated_voter_stage=' + json.dumps(dict(
    stage='baseline', voter=1, voter_instances=1, pid=os.getpid(),
    deployment_memory_qualified=False)), flush=True)
"""
        with tempfile.TemporaryDirectory() as temporary:
            result = OBSERVER.observe([sys.executable, "-c", program], os.environ.copy(),
                                      Path(temporary), 0)
        self.assertFalse(result["measurement_complete"])
        self.assertTrue(result["errors"])


if __name__ == "__main__":
    unittest.main()
