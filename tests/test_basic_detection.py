import os
import sys

# Bootstrap paths so conftest and agent modules are importable.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "agent"))

import json
import math
import os
import shutil
import signal as signal_mod
import tempfile
import time
import unittest
from unittest import mock

from conftest import make_event, RansomwareDetector, Mitigator, DEFAULT_WHITELISTED_PROCESSES, MAGIC_BYTES


# ---------------------------------------------------------------------------
# 4. Regression Tests d - Original Detection Still Works
# ---------------------------------------------------------------------------

class TestEntropyCalculation(unittest.TestCase):
    def setUp(self):
        self.detector = RansomwareDetector()

    def test_empty_data_returns_zero(self):
        self.assertEqual(self.detector.calculate_entropy(b""), 0)

    def test_single_byte_returns_zero(self):
        self.assertEqual(self.detector.calculate_entropy(b"\x00"), 0)

    def test_uniform_data_returns_zero(self):
        self.assertAlmostEqual(self.detector.calculate_entropy(b"AAAA"), 0.0)

    def test_two_equal_symbols(self):
        # "AB" → 1 bit of entropy
        self.assertAlmostEqual(self.detector.calculate_entropy(b"AB"), 1.0)

    def test_high_entropy_random_data(self):
        data = os.urandom(256)
        entropy = self.detector.calculate_entropy(data)
        self.assertGreater(entropy, 6.0)

    def test_max_entropy_all_unique_bytes(self):
        data = bytes(range(256))
        entropy = self.detector.calculate_entropy(data)
        self.assertAlmostEqual(entropy, 8.0, places=1)


class TestHighEntropyWriteDetection(unittest.TestCase):
    """Ensure the frequency + entropy heuristic still fires."""

    def test_high_entropy_burst_triggers_alert(self):
        """High-entropy writes should trigger either 'Magic bytes destroyed'
        (per-write, if entropy > 6.0 and no known header) or the cumulative
        'High entropy + Frequency' alert.  Both are valid ransomware signals.
        """
        det = RansomwareDetector(
            threshold_writes=5, time_window=10.0,
            verify_binary_hash=False, verify_lineage=False,
        )
        high_entropy_buf = os.urandom(128)
        for i in range(10):
            evt = make_event(1, 5000, "evil", f"/tmp/f{i}.dat", 128, high_entropy_buf)
            det.analyze_event(evt)
        # Accept either detection path — both indicate ransomware-like I/O.
        relevant = [
            a for a in det.alerts
            if a["reason"] in ("High entropy + Frequency", "Magic bytes destroyed")
        ]
        self.assertGreater(len(relevant), 0)

    def test_low_entropy_burst_does_not_trigger(self):
        det = RansomwareDetector(
            threshold_writes=5, time_window=10.0,
            verify_binary_hash=False, verify_lineage=False,
        )
        low_entropy_buf = b"\x00" * 128
        for i in range(10):
            evt = make_event(1, 5001, "writer", f"/tmp/f{i}.dat", 128, low_entropy_buf)
            det.analyze_event(evt)
        alerts = [a for a in det.alerts if a["reason"] == "High entropy + Frequency"]
        self.assertEqual(len(alerts), 0)


class TestSuspiciousExtensionDetection(unittest.TestCase):
    def test_open_locked_extension(self):
        det = RansomwareDetector(verify_binary_hash=False, verify_lineage=False)
        evt = make_event(0, 6000, "evil", "/home/user/file.locked", 0, b"")
        det.analyze_event(evt)
        self.assertEqual(len(det.alerts), 1)
        self.assertEqual(det.alerts[0]["reason"], "Suspicious extension")

    def test_rename_to_crypto_extension(self):
        det = RansomwareDetector(verify_binary_hash=False, verify_lineage=False)
        evt = make_event(2, 6001, "evil", "/home/user/file.crypto", 0, b"")
        det.analyze_event(evt)
        self.assertEqual(len(det.alerts), 1)
        self.assertEqual(det.alerts[0]["reason"], "Suspicious rename")

    def test_normal_extension_no_alert(self):
        det = RansomwareDetector(verify_binary_hash=False, verify_lineage=False)
        evt = make_event(0, 6002, "evil", "/home/user/file.txt", 0, b"")
        det.analyze_event(evt)
        self.assertEqual(len(det.alerts), 0)


class TestUnlinkDetection(unittest.TestCase):
    def test_high_frequency_unlinks_trigger_alert(self):
        det = RansomwareDetector(
            threshold_unlinks=3, time_window=10.0,
            verify_binary_hash=False, verify_lineage=False,
        )
        # Unlink frequency alert now requires at least one recent
        # high-entropy write as an entropy anchor.
        buf = os.urandom(128)
        evt = make_event(1, 7000, "evil", "/home/user/target.doc", 128, buf)
        det.analyze_event(evt)
        for i in range(5):
            evt = make_event(3, 7000, "evil", f"/tmp/f{i}.txt", 0, b"")
            det.analyze_event(evt)
        alerts = [a for a in det.alerts if a["reason"] == "High unlink frequency"]
        self.assertGreater(len(alerts), 0)

    def test_slow_unlinks_do_not_trigger(self):
        det = RansomwareDetector(
            threshold_unlinks=5, time_window=0.01,
            verify_binary_hash=False, verify_lineage=False,
        )
        for i in range(5):
            evt = make_event(3, 7001, "cleaner", f"/tmp/f{i}.txt", 0, b"")
            det.analyze_event(evt)
            time.sleep(0.02)  # Outside the tiny window
        alerts = [a for a in det.alerts if a["reason"] == "High unlink frequency"]
        self.assertEqual(len(alerts), 0)


# ---------------------------------------------------------------------------
# 3. Magic-Byte Analysis Tests
# ---------------------------------------------------------------------------

class TestMagicByteAnalysis(unittest.TestCase):
    """Verify detection of known file headers being overwritten."""

    def test_check_magic_bytes_pdf(self):
        buf = b"%PDF-1.4 rest of header..."
        self.assertEqual(RansomwareDetector.check_magic_bytes(buf), "PDF")

    def test_check_magic_bytes_png(self):
        buf = b"\x89PNG\r\n\x1a\n" + b"\x00" * 50
        self.assertEqual(RansomwareDetector.check_magic_bytes(buf), "PNG")

    def test_check_magic_bytes_jpeg(self):
        buf = b"\xff\xd8\xff\xe0" + b"\x00" * 50
        self.assertEqual(RansomwareDetector.check_magic_bytes(buf), "JPEG")

    def test_check_magic_bytes_zip(self):
        buf = b"PK\x03\x04" + b"\x00" * 50
        label = RansomwareDetector.check_magic_bytes(buf)
        self.assertIn(label, ("ZIP", "DOCX"))

    def test_check_magic_bytes_unknown(self):
        buf = os.urandom(64)
        # Extremely unlikely to match a known header.
        # If it does, just regenerate.
        result = RansomwareDetector.check_magic_bytes(buf)
        # We accept either None or a match (astronomically unlikely).
        # The important thing is no crash.
        self.assertIsInstance(result, (str, type(None)))

    def test_magic_bytes_destroyed_high_entropy(self):
        """Random data (no valid header + high entropy) → destroyed."""
        buf = os.urandom(128)
        entropy = RansomwareDetector().calculate_entropy(buf)
        # os.urandom(128) typically yields entropy ~6.3-6.8; the default
        # floor in magic_bytes_destroyed is 6.0 (tuned for eBPF 128-byte
        # samples).
        self.assertTrue(entropy > 6.0, f"Expected >6.0, got {entropy:.2f}")
        self.assertTrue(RansomwareDetector.magic_bytes_destroyed(buf, entropy))

    def test_magic_bytes_not_destroyed_valid_header(self):
        """A buffer that starts with a valid PDF header is NOT destroyed."""
        buf = b"%PDF" + os.urandom(124)
        entropy = RansomwareDetector().calculate_entropy(buf)
        self.assertFalse(RansomwareDetector.magic_bytes_destroyed(buf, entropy))

    def test_magic_bytes_not_destroyed_low_entropy(self):
        """Low-entropy data without a header is normal (e.g. text)."""
        buf = b"A" * 128
        entropy = RansomwareDetector().calculate_entropy(buf)
        self.assertFalse(RansomwareDetector.magic_bytes_destroyed(buf, entropy))

    def test_write_event_with_destroyed_header_triggers_critical(self):
        """End-to-end: in-place overwrites of multiple files → critical alert."""
        det = RansomwareDetector(verify_binary_hash=False, verify_lineage=False)
        high_entropy_buf = os.urandom(128)
        # Must overwrite 2+ distinct previously-opened files to trigger.
        for fname in ["/home/user/photo.jpg", "/home/user/doc.pdf"]:
            evt = make_event(0, 4000, "evil", fname, 0, b"")
            det.analyze_event(evt)
            evt = make_event(1, 4000, "evil", fname, 128, high_entropy_buf)
            det.analyze_event(evt)
        magic_alerts = [a for a in det.alerts if a["reason"] == "Magic bytes destroyed"]
        self.assertGreater(len(magic_alerts), 0)

    def test_write_event_with_valid_header_no_magic_alert(self):
        """A write that preserves the PDF header should not trigger magic alert."""
        det = RansomwareDetector(verify_binary_hash=False, verify_lineage=False)
        buf = b"%PDF" + b"\x00" * 124
        evt = make_event(1, 4001, "evil", "/home/user/doc.pdf", 128, buf)
        det.analyze_event(evt)
        magic_alerts = [a for a in det.alerts if a["reason"] == "Magic bytes destroyed"]
        self.assertEqual(len(magic_alerts), 0)


# ---------------------------------------------------------------------------
# 5. Integration / Combined Scenario Tests
# ---------------------------------------------------------------------------

class TestCombinedScenarios(unittest.TestCase):
    """Test realistic multi-signal scenarios."""

    def test_whitelisted_rsync_mass_delete_no_alerts(self):
        """rsync cleaning up old files should not trigger unlink alerts."""
        det = RansomwareDetector(
            threshold_unlinks=3, time_window=10.0,
            verify_binary_hash=False, verify_lineage=False,
        )
        for i in range(50):
            evt = make_event(3, 8001, "rsync", f"/backup/old_{i}.bak", 0, b"")
            det.analyze_event(evt)
        self.assertEqual(len(det.alerts), 0)

    def test_unknown_process_ransomware_full_chain(self):
        """An unknown process doing writes + renames + deletes → multiple alerts."""
        det = RansomwareDetector(
            threshold_writes=3, threshold_unlinks=3, time_window=10.0,
            verify_binary_hash=False, verify_lineage=False,
        )
        buf = os.urandom(128)
        # High-entropy writes
        for i in range(5):
            evt = make_event(1, 9000, "cryptolocker", f"/home/f{i}.doc", 128, buf)
            det.analyze_event(evt)
        # Rename to .locked
        evt = make_event(2, 9000, "cryptolocker", "/home/f0.locked", 0, b"")
        det.analyze_event(evt)
        # Mass delete originals
        for i in range(5):
            evt = make_event(3, 9000, "cryptolocker", f"/home/f{i}.doc", 0, b"")
            det.analyze_event(evt)

        reasons = {a["reason"] for a in det.alerts}
        # Should see at least magic-bytes or entropy alerts, rename, and unlink.
        self.assertTrue(len(det.alerts) >= 3, f"Expected >=3 alerts, got {det.alerts}")
        self.assertIn("Suspicious rename", reasons)


if __name__ == "__main__":
    unittest.main()
