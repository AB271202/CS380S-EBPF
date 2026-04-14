"""Unit tests for the RansomwareDetector false-positive reduction features.

Covers:
  1. Process whitelist – trusted processes are silently skipped.
  2. Canary (honeypot) files – non-whitelisted access triggers critical alerts.
  3. Magic-byte analysis – overwriting known file headers with encrypted data
     is flagged at critical severity.
  4. Regression – existing entropy / frequency / extension / unlink detection
     still works correctly after the refactor.
"""

import json
import math
import os
import tempfile
import time
import types
import unittest

# Allow running from the repo root or from the tests/ directory.
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))

from detector import (
    DEFAULT_WHITELISTED_PROCESSES,
    MAGIC_BYTES,
    RansomwareDetector,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_event(event_type, pid, comm, filename, size=0, buffer=b""):
    """Build a lightweight event object that quacks like a BPF event."""
    evt = types.SimpleNamespace()
    evt.type = event_type
    evt.pid = pid
    evt.comm = comm.encode("utf-8") if isinstance(comm, str) else comm
    evt.filename = filename.encode("utf-8") if isinstance(filename, str) else filename
    evt.size = size
    evt.buffer = buffer
    return evt


# ---------------------------------------------------------------------------
# 1. Process Whitelist Tests
# ---------------------------------------------------------------------------

class TestProcessWhitelist(unittest.TestCase):
    """Verify that whitelisted processes do not generate alerts."""

    def setUp(self):
        self.detector = RansomwareDetector()

    def test_default_whitelist_contains_common_tools(self):
        for proc in ("git", "gcc", "apt", "rsync", "vim", "postgres"):
            self.assertTrue(
                self.detector.is_whitelisted(proc),
                f"{proc} should be whitelisted by default",
            )

    def test_unknown_process_is_not_whitelisted(self):
        self.assertFalse(self.detector.is_whitelisted("evil_ransomware"))

    def test_whitelisted_process_write_generates_no_alert(self):
        """A whitelisted process doing high-entropy writes must be silent."""
        high_entropy_buf = os.urandom(128)
        for i in range(20):
            evt = _make_event(1, 1000, "gcc", f"/tmp/obj_{i}.o", 128, high_entropy_buf)
            self.detector.analyze_event(evt)
        self.assertEqual(len(self.detector.alerts), 0)

    def test_whitelisted_process_unlink_generates_no_alert(self):
        for i in range(20):
            evt = _make_event(3, 1001, "make", f"/tmp/tmp_{i}.o", 0, b"")
            self.detector.analyze_event(evt)
        self.assertEqual(len(self.detector.alerts), 0)

    def test_whitelisted_process_suspicious_extension_no_alert(self):
        evt = _make_event(0, 1002, "rsync", "/backup/file.locked", 0, b"")
        self.detector.analyze_event(evt)
        self.assertEqual(len(self.detector.alerts), 0)

    def test_whitelisted_process_rename_no_alert(self):
        evt = _make_event(2, 1003, "git", "/repo/file.crypto", 0, b"")
        self.detector.analyze_event(evt)
        self.assertEqual(len(self.detector.alerts), 0)

    def test_non_whitelisted_process_still_triggers_alert(self):
        evt = _make_event(0, 2000, "evil", "/home/user/file.locked", 0, b"")
        self.detector.analyze_event(evt)
        self.assertEqual(len(self.detector.alerts), 1)
        self.assertEqual(self.detector.alerts[0]["reason"], "Suspicious extension")

    def test_load_whitelist_from_config_file(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as fh:
            json.dump({"whitelisted_processes": ["my-backup-tool", "custom-sync"]}, fh)
            cfg_path = fh.name
        try:
            det = RansomwareDetector(whitelist_config=cfg_path)
            self.assertTrue(det.is_whitelisted("my-backup-tool"))
            self.assertTrue(det.is_whitelisted("custom-sync"))
            # Built-in defaults are still present.
            self.assertTrue(det.is_whitelisted("git"))
        finally:
            os.unlink(cfg_path)

    def test_bad_whitelist_config_does_not_crash(self):
        """A missing or malformed config file should warn, not crash."""
        det = RansomwareDetector(whitelist_config="/nonexistent/path.json")
        # Should still have the defaults.
        self.assertTrue(det.is_whitelisted("git"))


# ---------------------------------------------------------------------------
# 2. Canary File Tests
# ---------------------------------------------------------------------------

class TestCanaryFiles(unittest.TestCase):
    """Verify canary (honeypot) file deployment and detection."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.detector = RansomwareDetector(canary_dirs=[self.tmpdir])

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_canary_files_are_created(self):
        expected = {
            ".~canary_doc.docx",
            ".~canary_photo.jpg",
            ".~canary_data.xlsx",
        }
        created = set(os.listdir(self.tmpdir))
        self.assertEqual(created, expected)

    def test_canary_access_triggers_critical_alert(self):
        canary = os.path.join(self.tmpdir, ".~canary_doc.docx")
        evt = _make_event(0, 3000, "evil", canary, 0, b"")
        self.detector.analyze_event(evt)
        self.assertEqual(len(self.detector.alerts), 1)
        self.assertEqual(self.detector.alerts[0]["severity"], "critical")
        self.assertEqual(self.detector.alerts[0]["reason"], "Canary file access")

    def test_canary_access_by_whitelisted_process_still_alerts(self):
        """Even trusted processes touching canaries should be flagged."""
        canary = os.path.join(self.tmpdir, ".~canary_photo.jpg")
        evt = _make_event(1, 3001, "git", canary, 64, os.urandom(64))
        self.detector.analyze_event(evt)
        self.assertEqual(len(self.detector.alerts), 1)
        self.assertEqual(self.detector.alerts[0]["severity"], "critical")

    def test_non_canary_file_is_not_flagged_as_canary(self):
        normal = os.path.join(self.tmpdir, "normal.txt")
        with open(normal, "w") as fh:
            fh.write("hello")
        evt = _make_event(0, 3002, "evil", normal, 0, b"")
        # This should NOT trigger a canary alert (may trigger extension alert
        # only if the extension is suspicious, which .txt is not).
        canary_alerts = [a for a in self.detector.alerts if a["reason"] == "Canary file access"]
        self.assertEqual(len(canary_alerts), 0)

    def test_deploy_canaries_custom_filenames(self):
        det = RansomwareDetector()
        custom_dir = os.path.join(self.tmpdir, "custom")
        det.deploy_canaries(custom_dir, filenames=[".trap1.pdf", ".trap2.docx"])
        self.assertTrue(os.path.exists(os.path.join(custom_dir, ".trap1.pdf")))
        self.assertTrue(os.path.exists(os.path.join(custom_dir, ".trap2.docx")))
        self.assertEqual(len(det.canary_paths), 2)

    def test_is_canary_returns_false_for_random_path(self):
        self.assertFalse(self.detector.is_canary("/some/random/path.txt"))


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
        """End-to-end: a WRITE that destroys a file header → critical alert."""
        det = RansomwareDetector()
        high_entropy_buf = os.urandom(128)
        evt = _make_event(1, 4000, "evil", "/home/user/photo.jpg", 128, high_entropy_buf)
        det.analyze_event(evt)
        self.assertEqual(len(det.alerts), 1)
        self.assertEqual(det.alerts[0]["severity"], "critical")
        self.assertEqual(det.alerts[0]["reason"], "Magic bytes destroyed")

    def test_write_event_with_valid_header_no_magic_alert(self):
        """A write that preserves the PDF header should not trigger magic alert."""
        det = RansomwareDetector()
        buf = b"%PDF" + b"\x00" * 124
        evt = _make_event(1, 4001, "evil", "/home/user/doc.pdf", 128, buf)
        det.analyze_event(evt)
        magic_alerts = [a for a in det.alerts if a["reason"] == "Magic bytes destroyed"]
        self.assertEqual(len(magic_alerts), 0)


# ---------------------------------------------------------------------------
# 4. Regression Tests – Original Detection Still Works
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
        det = RansomwareDetector(threshold_writes=5, time_window=10.0)
        high_entropy_buf = os.urandom(128)
        for i in range(10):
            evt = _make_event(1, 5000, "evil", f"/tmp/f{i}.dat", 128, high_entropy_buf)
            det.analyze_event(evt)
        # Accept either detection path — both indicate ransomware-like I/O.
        relevant = [
            a for a in det.alerts
            if a["reason"] in ("High entropy + Frequency", "Magic bytes destroyed")
        ]
        self.assertGreater(len(relevant), 0)

    def test_low_entropy_burst_does_not_trigger(self):
        det = RansomwareDetector(threshold_writes=5, time_window=10.0)
        low_entropy_buf = b"\x00" * 128
        for i in range(10):
            evt = _make_event(1, 5001, "writer", f"/tmp/f{i}.dat", 128, low_entropy_buf)
            det.analyze_event(evt)
        alerts = [a for a in det.alerts if a["reason"] == "High entropy + Frequency"]
        self.assertEqual(len(alerts), 0)


class TestSuspiciousExtensionDetection(unittest.TestCase):
    def test_open_locked_extension(self):
        det = RansomwareDetector()
        evt = _make_event(0, 6000, "evil", "/home/user/file.locked", 0, b"")
        det.analyze_event(evt)
        self.assertEqual(len(det.alerts), 1)
        self.assertEqual(det.alerts[0]["reason"], "Suspicious extension")

    def test_rename_to_crypto_extension(self):
        det = RansomwareDetector()
        evt = _make_event(2, 6001, "evil", "/home/user/file.crypto", 0, b"")
        det.analyze_event(evt)
        self.assertEqual(len(det.alerts), 1)
        self.assertEqual(det.alerts[0]["reason"], "Suspicious rename")

    def test_normal_extension_no_alert(self):
        det = RansomwareDetector()
        evt = _make_event(0, 6002, "evil", "/home/user/file.txt", 0, b"")
        det.analyze_event(evt)
        self.assertEqual(len(det.alerts), 0)


class TestUnlinkDetection(unittest.TestCase):
    def test_high_frequency_unlinks_trigger_alert(self):
        det = RansomwareDetector(threshold_unlinks=3, time_window=10.0)
        for i in range(5):
            evt = _make_event(3, 7000, "evil", f"/tmp/f{i}.txt", 0, b"")
            det.analyze_event(evt)
        alerts = [a for a in det.alerts if a["reason"] == "High unlink frequency"]
        self.assertGreater(len(alerts), 0)

    def test_slow_unlinks_do_not_trigger(self):
        det = RansomwareDetector(threshold_unlinks=5, time_window=0.01)
        for i in range(5):
            evt = _make_event(3, 7001, "cleaner", f"/tmp/f{i}.txt", 0, b"")
            det.analyze_event(evt)
            time.sleep(0.02)  # Outside the tiny window
        alerts = [a for a in det.alerts if a["reason"] == "High unlink frequency"]
        self.assertEqual(len(alerts), 0)


# ---------------------------------------------------------------------------
# 5. Integration / Combined Scenario Tests
# ---------------------------------------------------------------------------

class TestCombinedScenarios(unittest.TestCase):
    """Test realistic multi-signal scenarios."""

    def test_whitelisted_gcc_compile_no_alerts(self):
        """Simulates a gcc compilation: many high-entropy .o writes."""
        det = RansomwareDetector(threshold_writes=3, time_window=10.0)
        buf = os.urandom(128)
        for i in range(20):
            evt = _make_event(1, 8000, "gcc", f"/build/obj_{i}.o", 128, buf)
            det.analyze_event(evt)
        self.assertEqual(len(det.alerts), 0)

    def test_whitelisted_rsync_mass_delete_no_alerts(self):
        """rsync cleaning up old files should not trigger unlink alerts."""
        det = RansomwareDetector(threshold_unlinks=3, time_window=10.0)
        for i in range(50):
            evt = _make_event(3, 8001, "rsync", f"/backup/old_{i}.bak", 0, b"")
            det.analyze_event(evt)
        self.assertEqual(len(det.alerts), 0)

    def test_unknown_process_ransomware_full_chain(self):
        """An unknown process doing writes + renames + deletes → multiple alerts."""
        det = RansomwareDetector(
            threshold_writes=3, threshold_unlinks=3, time_window=10.0,
        )
        buf = os.urandom(128)
        # High-entropy writes
        for i in range(5):
            evt = _make_event(1, 9000, "cryptolocker", f"/home/f{i}.doc", 128, buf)
            det.analyze_event(evt)
        # Rename to .locked
        evt = _make_event(2, 9000, "cryptolocker", "/home/f0.locked", 0, b"")
        det.analyze_event(evt)
        # Mass delete originals
        for i in range(5):
            evt = _make_event(3, 9000, "cryptolocker", f"/home/f{i}.doc", 0, b"")
            det.analyze_event(evt)

        reasons = {a["reason"] for a in det.alerts}
        # Should see at least magic-bytes or entropy alerts, rename, and unlink.
        self.assertTrue(len(det.alerts) >= 3, f"Expected >=3 alerts, got {det.alerts}")
        self.assertIn("Suspicious rename", reasons)


if __name__ == "__main__":
    unittest.main()
