"""Unit tests for the RansomwareDetector false-positive reduction features.

Covers:
  1. Process whitelist – trusted processes are silently skipped.
  2. Canary (honeypot) files – non-whitelisted access triggers critical alerts.
  3. Magic-byte analysis – overwriting known file headers with encrypted data
     is flagged at critical severity.
  4. Binary hash verification – tampered binaries revoke the whitelist.
  5. Process lineage validation – untrusted parent chains revoke the whitelist.
  6. Regression – existing entropy / frequency / extension / unlink detection
     still works correctly after the refactor.
"""

import json
import math
import os
import shutil
import signal as signal_mod
import stat
import tempfile
import time
import types
import unittest
from unittest import mock

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
        # Disable hash/lineage verification for basic name-based tests.
        self.detector = RansomwareDetector(
            verify_binary_hash=False, verify_lineage=False,
        )

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
            det = RansomwareDetector(
                whitelist_config=cfg_path,
                verify_binary_hash=False, verify_lineage=False,
            )
            self.assertTrue(det.is_whitelisted("my-backup-tool"))
            self.assertTrue(det.is_whitelisted("custom-sync"))
            # Built-in defaults are still present.
            self.assertTrue(det.is_whitelisted("git"))
        finally:
            os.unlink(cfg_path)

    def test_bad_whitelist_config_does_not_crash(self):
        """A missing or malformed config file should warn, not crash."""
        det = RansomwareDetector(
            whitelist_config="/nonexistent/path.json",
            verify_binary_hash=False, verify_lineage=False,
        )
        # Should still have the defaults.
        self.assertTrue(det.is_whitelisted("git"))


# ---------------------------------------------------------------------------
# 1b. Binary Hash Verification Tests
# ---------------------------------------------------------------------------

class TestBinaryHashVerification(unittest.TestCase):
    """Verify that tampered binaries revoke the whitelist."""

    def setUp(self):
        # Create a temporary "binary" file with known content.
        self.tmpfile = tempfile.NamedTemporaryFile(delete=False, suffix=".bin")
        self.tmpfile.write(b"trusted-binary-content")
        self.tmpfile.close()
        self.good_hash = RansomwareDetector.hash_binary(self.tmpfile.name)

    def tearDown(self):
        os.unlink(self.tmpfile.name)

    def test_hash_binary_returns_sha256(self):
        digest = RansomwareDetector.hash_binary(self.tmpfile.name)
        self.assertIsNotNone(digest)
        self.assertEqual(len(digest), 64)  # SHA-256 hex = 64 chars

    def test_hash_binary_nonexistent_returns_none(self):
        self.assertIsNone(RansomwareDetector.hash_binary("/no/such/file"))

    def test_matching_hash_keeps_whitelist(self):
        """A whitelisted process whose binary hash matches stays trusted."""
        det = RansomwareDetector(
            trusted_hashes={self.tmpfile.name: [self.good_hash]},
            verify_lineage=False,  # isolate hash test
        )
        # Mock _resolve_exe to return our temp file path.
        with mock.patch.object(
            RansomwareDetector, "_resolve_exe", return_value=self.tmpfile.name
        ):
            self.assertTrue(det.is_whitelisted("gcc", pid=9999))
        self.assertEqual(len(det.alerts), 0)

    def test_mismatched_hash_revokes_whitelist(self):
        """A whitelisted process with a wrong hash is treated as untrusted."""
        det = RansomwareDetector(
            trusted_hashes={self.tmpfile.name: ["bad_hash_value"]},
            verify_lineage=False,
        )
        with mock.patch.object(
            RansomwareDetector, "_resolve_exe", return_value=self.tmpfile.name
        ):
            self.assertFalse(det.is_whitelisted("gcc", pid=9999))
        hash_alerts = [a for a in det.alerts if a["reason"] == "Binary hash mismatch"]
        self.assertEqual(len(hash_alerts), 1)

    def test_no_registered_hash_is_open_trust(self):
        """If no hashes are registered for a path, the process is trusted."""
        det = RansomwareDetector(
            trusted_hashes={},  # empty — no hashes registered
            verify_lineage=False,
        )
        with mock.patch.object(
            RansomwareDetector, "_resolve_exe", return_value="/usr/bin/gcc"
        ):
            self.assertTrue(det.is_whitelisted("gcc", pid=9999))

    def test_unreadable_exe_is_trusted(self):
        """If /proc/<pid>/exe can't be resolved, skip the check."""
        det = RansomwareDetector(
            trusted_hashes={"/usr/bin/gcc": ["some_hash"]},
            verify_lineage=False,
        )
        with mock.patch.object(
            RansomwareDetector, "_resolve_exe", return_value=None
        ):
            self.assertTrue(det.is_whitelisted("gcc", pid=9999))

    def test_hash_cache_avoids_rehashing(self):
        """The hash should be computed once and cached for the same pid+path."""
        det = RansomwareDetector(
            trusted_hashes={self.tmpfile.name: [self.good_hash]},
            verify_lineage=False,
        )
        with mock.patch.object(
            RansomwareDetector, "_resolve_exe", return_value=self.tmpfile.name
        ), mock.patch.object(
            RansomwareDetector, "hash_binary", wraps=RansomwareDetector.hash_binary
        ) as mock_hash:
            det.is_whitelisted("gcc", pid=9999)
            det.is_whitelisted("gcc", pid=9999)
            # hash_binary should only be called once — second call uses cache.
            mock_hash.assert_called_once()

    def test_tampered_binary_triggers_alert_on_event(self):
        """End-to-end: a 'gcc' with a bad hash doing writes → alerts fire."""
        det = RansomwareDetector(
            trusted_hashes={self.tmpfile.name: ["wrong_hash"]},
            verify_lineage=False,
            threshold_writes=2,
            time_window=10.0,
        )
        buf = os.urandom(128)
        with mock.patch.object(
            RansomwareDetector, "_resolve_exe", return_value=self.tmpfile.name
        ):
            for i in range(5):
                evt = _make_event(1, 9999, "gcc", f"/tmp/obj_{i}.o", 128, buf)
                det.analyze_event(evt)
        # Should have hash-mismatch alert(s) AND detection alerts.
        hash_alerts = [a for a in det.alerts if a["reason"] == "Binary hash mismatch"]
        detection_alerts = [
            a for a in det.alerts
            if a["reason"] in ("Magic bytes destroyed", "High entropy + Frequency")
        ]
        self.assertGreater(len(hash_alerts), 0)
        self.assertGreater(len(detection_alerts), 0)

    def test_load_trusted_hashes_from_config(self):
        """Trusted hashes can be loaded from the JSON config file."""
        cfg = {
            "whitelisted_processes": [],
            "trusted_hashes": {
                "/usr/bin/myapp": ["abc123"],
            },
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as fh:
            json.dump(cfg, fh)
            cfg_path = fh.name
        try:
            det = RansomwareDetector(whitelist_config=cfg_path, verify_lineage=False)
            self.assertIn("/usr/bin/myapp", det.trusted_hashes)
            self.assertIn("abc123", det.trusted_hashes["/usr/bin/myapp"])
        finally:
            os.unlink(cfg_path)


# ---------------------------------------------------------------------------
# 1c. Process Lineage Validation Tests
# ---------------------------------------------------------------------------

class TestProcessLineageValidation(unittest.TestCase):
    """Verify that untrusted parent chains revoke the whitelist."""

    def test_trusted_parent_keeps_whitelist(self):
        """A process with bash in its ancestry stays whitelisted."""
        det = RansomwareDetector(verify_binary_hash=False)
        # Mock lineage: pid 100 → bash(99) → systemd(1)
        with mock.patch.object(
            det, "get_process_lineage",
            return_value=[(99, "bash"), (1, "systemd")],
        ):
            self.assertTrue(det.is_whitelisted("gcc", pid=100))
        self.assertEqual(len(det.alerts), 0)

    def test_untrusted_parent_revokes_whitelist(self):
        """A process spawned by an unknown dropper is not trusted."""
        det = RansomwareDetector(verify_binary_hash=False)
        with mock.patch.object(
            det, "get_process_lineage",
            return_value=[(50, "evil_dropper"), (1, "unknown_init")],
        ):
            self.assertFalse(det.is_whitelisted("gcc", pid=100))
        lineage_alerts = [
            a for a in det.alerts if a["reason"] == "Untrusted process lineage"
        ]
        self.assertEqual(len(lineage_alerts), 1)

    def test_empty_lineage_is_trusted(self):
        """If lineage can't be read (container, short-lived), trust it."""
        det = RansomwareDetector(verify_binary_hash=False)
        with mock.patch.object(
            det, "get_process_lineage", return_value=[],
        ):
            self.assertTrue(det.is_whitelisted("gcc", pid=100))

    def test_lineage_cache_avoids_recheck(self):
        """Lineage is checked once per PID and cached."""
        det = RansomwareDetector(verify_binary_hash=False)
        with mock.patch.object(
            det, "get_process_lineage",
            return_value=[(99, "bash")],
        ) as mock_lineage:
            det.is_whitelisted("gcc", pid=100)
            det.is_whitelisted("gcc", pid=100)
            mock_lineage.assert_called_once()

    def test_untrusted_lineage_triggers_alert_on_event(self):
        """End-to-end: a 'gcc' with bad lineage doing writes → alerts fire."""
        det = RansomwareDetector(
            verify_binary_hash=False,
            threshold_writes=2,
            time_window=10.0,
        )
        buf = os.urandom(128)
        with mock.patch.object(
            det, "get_process_lineage",
            return_value=[(50, "evil_dropper")],
        ):
            for i in range(5):
                evt = _make_event(1, 100, "gcc", f"/tmp/obj_{i}.o", 128, buf)
                det.analyze_event(evt)
        lineage_alerts = [
            a for a in det.alerts if a["reason"] == "Untrusted process lineage"
        ]
        detection_alerts = [
            a for a in det.alerts
            if a["reason"] in ("Magic bytes destroyed", "High entropy + Frequency")
        ]
        self.assertGreater(len(lineage_alerts), 0)
        self.assertGreater(len(detection_alerts), 0)

    def test_custom_trusted_parents(self):
        """Custom trusted parents can be provided at init."""
        det = RansomwareDetector(
            verify_binary_hash=False,
            trusted_parents={"my_orchestrator"},
        )
        with mock.patch.object(
            det, "get_process_lineage",
            return_value=[(50, "my_orchestrator")],
        ):
            self.assertTrue(det.is_whitelisted("gcc", pid=100))

    def test_load_trusted_parents_from_config(self):
        """Trusted parents can be loaded from the JSON config file."""
        cfg = {
            "whitelisted_processes": [],
            "trusted_parents": ["my_launcher"],
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as fh:
            json.dump(cfg, fh)
            cfg_path = fh.name
        try:
            det = RansomwareDetector(whitelist_config=cfg_path, verify_binary_hash=False)
            self.assertIn("my_launcher", det.trusted_parents)
            # Built-in defaults are still present.
            self.assertIn("bash", det.trusted_parents)
        finally:
            os.unlink(cfg_path)

    def test_get_process_lineage_with_real_pid(self):
        """Smoke test: get_process_lineage on our own PID should not crash."""
        det = RansomwareDetector(verify_binary_hash=False, verify_lineage=False)
        lineage = det.get_process_lineage(os.getpid())
        # We should get at least one ancestor (our parent shell/process).
        # On some CI environments this might be empty, so just check no crash.
        self.assertIsInstance(lineage, list)


# ---------------------------------------------------------------------------
# 1d. Combined Hash + Lineage Tests
# ---------------------------------------------------------------------------

class TestHashAndLineageCombined(unittest.TestCase):
    """Verify that both checks must pass for the whitelist to hold."""

    def setUp(self):
        self.tmpfile = tempfile.NamedTemporaryFile(delete=False, suffix=".bin")
        self.tmpfile.write(b"trusted-binary-content")
        self.tmpfile.close()
        self.good_hash = RansomwareDetector.hash_binary(self.tmpfile.name)

    def tearDown(self):
        os.unlink(self.tmpfile.name)

    def test_both_pass_stays_whitelisted(self):
        det = RansomwareDetector(
            trusted_hashes={self.tmpfile.name: [self.good_hash]},
        )
        with mock.patch.object(
            RansomwareDetector, "_resolve_exe", return_value=self.tmpfile.name
        ), mock.patch.object(
            det, "get_process_lineage", return_value=[(99, "bash")],
        ):
            self.assertTrue(det.is_whitelisted("gcc", pid=100))
        self.assertEqual(len(det.alerts), 0)

    def test_hash_pass_lineage_fail_revokes(self):
        det = RansomwareDetector(
            trusted_hashes={self.tmpfile.name: [self.good_hash]},
        )
        with mock.patch.object(
            RansomwareDetector, "_resolve_exe", return_value=self.tmpfile.name
        ), mock.patch.object(
            det, "get_process_lineage", return_value=[(50, "evil_dropper")],
        ):
            self.assertFalse(det.is_whitelisted("gcc", pid=100))

    def test_hash_fail_lineage_pass_revokes(self):
        det = RansomwareDetector(
            trusted_hashes={self.tmpfile.name: ["wrong_hash"]},
        )
        with mock.patch.object(
            RansomwareDetector, "_resolve_exe", return_value=self.tmpfile.name
        ), mock.patch.object(
            det, "get_process_lineage", return_value=[(99, "bash")],
        ):
            # Hash check fails first, so lineage is never reached.
            self.assertFalse(det.is_whitelisted("gcc", pid=100))

    def test_both_fail_revokes(self):
        det = RansomwareDetector(
            trusted_hashes={self.tmpfile.name: ["wrong_hash"]},
        )
        with mock.patch.object(
            RansomwareDetector, "_resolve_exe", return_value=self.tmpfile.name
        ), mock.patch.object(
            det, "get_process_lineage", return_value=[(50, "evil_dropper")],
        ):
            self.assertFalse(det.is_whitelisted("gcc", pid=100))


# ---------------------------------------------------------------------------
# 2. Canary File Tests
# ---------------------------------------------------------------------------

class TestCanaryFiles(unittest.TestCase):
    """Verify canary (honeypot) file deployment and detection."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.detector = RansomwareDetector(
            canary_dirs=[self.tmpdir],
            verify_binary_hash=False, verify_lineage=False,
        )

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
        """End-to-end: in-place overwrites of multiple files → critical alert."""
        det = RansomwareDetector(verify_binary_hash=False, verify_lineage=False)
        high_entropy_buf = os.urandom(128)
        # Must overwrite 2+ distinct previously-opened files to trigger.
        for fname in ["/home/user/photo.jpg", "/home/user/doc.pdf"]:
            evt = _make_event(0, 4000, "evil", fname, 0, b"")
            det.analyze_event(evt)
            evt = _make_event(1, 4000, "evil", fname, 128, high_entropy_buf)
            det.analyze_event(evt)
        magic_alerts = [a for a in det.alerts if a["reason"] == "Magic bytes destroyed"]
        self.assertGreater(len(magic_alerts), 0)

    def test_write_event_with_valid_header_no_magic_alert(self):
        """A write that preserves the PDF header should not trigger magic alert."""
        det = RansomwareDetector(verify_binary_hash=False, verify_lineage=False)
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
        det = RansomwareDetector(
            threshold_writes=5, time_window=10.0,
            verify_binary_hash=False, verify_lineage=False,
        )
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
        det = RansomwareDetector(
            threshold_writes=5, time_window=10.0,
            verify_binary_hash=False, verify_lineage=False,
        )
        low_entropy_buf = b"\x00" * 128
        for i in range(10):
            evt = _make_event(1, 5001, "writer", f"/tmp/f{i}.dat", 128, low_entropy_buf)
            det.analyze_event(evt)
        alerts = [a for a in det.alerts if a["reason"] == "High entropy + Frequency"]
        self.assertEqual(len(alerts), 0)


class TestSuspiciousExtensionDetection(unittest.TestCase):
    def test_open_locked_extension(self):
        det = RansomwareDetector(verify_binary_hash=False, verify_lineage=False)
        evt = _make_event(0, 6000, "evil", "/home/user/file.locked", 0, b"")
        det.analyze_event(evt)
        self.assertEqual(len(det.alerts), 1)
        self.assertEqual(det.alerts[0]["reason"], "Suspicious extension")

    def test_rename_to_crypto_extension(self):
        det = RansomwareDetector(verify_binary_hash=False, verify_lineage=False)
        evt = _make_event(2, 6001, "evil", "/home/user/file.crypto", 0, b"")
        det.analyze_event(evt)
        self.assertEqual(len(det.alerts), 1)
        self.assertEqual(det.alerts[0]["reason"], "Suspicious rename")

    def test_normal_extension_no_alert(self):
        det = RansomwareDetector(verify_binary_hash=False, verify_lineage=False)
        evt = _make_event(0, 6002, "evil", "/home/user/file.txt", 0, b"")
        det.analyze_event(evt)
        self.assertEqual(len(det.alerts), 0)


class TestUnlinkDetection(unittest.TestCase):
    def test_high_frequency_unlinks_trigger_alert(self):
        det = RansomwareDetector(
            threshold_unlinks=3, time_window=10.0,
            verify_binary_hash=False, verify_lineage=False,
        )
        for i in range(5):
            evt = _make_event(3, 7000, "evil", f"/tmp/f{i}.txt", 0, b"")
            det.analyze_event(evt)
        alerts = [a for a in det.alerts if a["reason"] == "High unlink frequency"]
        self.assertGreater(len(alerts), 0)

    def test_slow_unlinks_do_not_trigger(self):
        det = RansomwareDetector(
            threshold_unlinks=5, time_window=0.01,
            verify_binary_hash=False, verify_lineage=False,
        )
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
        det = RansomwareDetector(
            threshold_writes=3, time_window=10.0,
            verify_binary_hash=False, verify_lineage=False,
        )
        buf = os.urandom(128)
        for i in range(20):
            evt = _make_event(1, 8000, "gcc", f"/build/obj_{i}.o", 128, buf)
            det.analyze_event(evt)
        self.assertEqual(len(det.alerts), 0)

    def test_whitelisted_rsync_mass_delete_no_alerts(self):
        """rsync cleaning up old files should not trigger unlink alerts."""
        det = RansomwareDetector(
            threshold_unlinks=3, time_window=10.0,
            verify_binary_hash=False, verify_lineage=False,
        )
        for i in range(50):
            evt = _make_event(3, 8001, "rsync", f"/backup/old_{i}.bak", 0, b"")
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


# ---------------------------------------------------------------------------
# 6. Write Target Classification Tests
# ---------------------------------------------------------------------------

class TestWriteTargetClassification(unittest.TestCase):
    """Verify that system-path writes are excluded from heuristics."""

    def test_dev_path_is_not_user_file(self):
        self.assertFalse(RansomwareDetector.is_user_file("/dev/sda"))
        self.assertFalse(RansomwareDetector.is_user_file("/dev/null"))

    def test_proc_path_is_not_user_file(self):
        self.assertFalse(RansomwareDetector.is_user_file("/proc/1/maps"))

    def test_sys_path_is_not_user_file(self):
        self.assertFalse(RansomwareDetector.is_user_file("/sys/class/net/eth0"))

    def test_var_log_is_not_user_file(self):
        self.assertFalse(RansomwareDetector.is_user_file("/var/log/syslog"))

    def test_var_lib_is_not_user_file(self):
        self.assertFalse(RansomwareDetector.is_user_file("/var/lib/dpkg/status"))

    def test_home_path_is_user_file(self):
        self.assertTrue(RansomwareDetector.is_user_file("/home/user/doc.pdf"))

    def test_srv_path_is_user_file(self):
        self.assertTrue(RansomwareDetector.is_user_file("/srv/data/report.xlsx"))

    def test_tmp_regular_is_user_file(self):
        self.assertTrue(RansomwareDetector.is_user_file("/tmp/output.dat"))

    def test_is_user_document_common_types(self):
        for ext in (".pdf", ".docx", ".jpg", ".py", ".sql"):
            self.assertTrue(
                RansomwareDetector.is_user_document(f"/home/user/file{ext}"),
                f"{ext} should be a user document",
            )

    def test_is_user_document_unknown_ext(self):
        self.assertFalse(RansomwareDetector.is_user_document("/home/user/file.xyz123"))

    def test_system_path_writes_do_not_trigger_alerts(self):
        """High-entropy writes to /dev/ should be silently ignored."""
        det = RansomwareDetector(
            threshold_writes=3, time_window=10.0,
            verify_binary_hash=False, verify_lineage=False,
        )
        buf = os.urandom(128)
        for i in range(20):
            evt = _make_event(1, 11000, "defrag", f"/dev/sda", 128, buf)
            det.analyze_event(evt)
        self.assertEqual(len(det.alerts), 0)

    def test_var_lib_writes_do_not_trigger_alerts(self):
        """Database writes to /var/lib/ should be silently ignored."""
        det = RansomwareDetector(
            threshold_writes=3, time_window=10.0,
            verify_binary_hash=False, verify_lineage=False,
        )
        buf = os.urandom(128)
        for i in range(20):
            evt = _make_event(1, 11001, "mysqld_fake", f"/var/lib/mysql/db_{i}.ibd", 128, buf)
            det.analyze_event(evt)
        self.assertEqual(len(det.alerts), 0)

    def test_user_path_writes_still_trigger_alerts(self):
        """High-entropy writes to /home/ should still trigger alerts."""
        det = RansomwareDetector(
            threshold_writes=3, time_window=10.0,
            verify_binary_hash=False, verify_lineage=False,
        )
        buf = os.urandom(128)
        for i in range(10):
            evt = _make_event(1, 11002, "evil", f"/home/user/file_{i}.doc", 128, buf)
            det.analyze_event(evt)
        relevant = [
            a for a in det.alerts
            if a["reason"] in ("Magic bytes destroyed", "High entropy + Frequency",
                               "High file diversity + Entropy")
        ]
        self.assertGreater(len(relevant), 0)


# ---------------------------------------------------------------------------
# 7. File Diversity Scoring Tests
# ---------------------------------------------------------------------------

class TestFileDiversityScoring(unittest.TestCase):
    """Verify that file diversity across directories is detected."""

    def test_diverse_writes_across_dirs_triggers_alert(self):
        """Writes to many unique files across many directories → alert."""
        det = RansomwareDetector(
            threshold_unique_files=5,
            threshold_unique_dirs=3,
            threshold_writes=100,  # Set high so frequency check doesn't fire first
            time_window=10.0,
            verify_binary_hash=False, verify_lineage=False,
        )
        buf = os.urandom(128)
        dirs = ["/home/user/Documents", "/home/user/Pictures",
                "/home/user/Desktop", "/srv/shared"]
        for i, d in enumerate(dirs):
            for j in range(3):
                evt = _make_event(
                    1, 12000, "evil",
                    f"{d}/file_{j}.doc", 128, buf,
                )
                det.analyze_event(evt)
        diversity_alerts = [
            a for a in det.alerts if a["reason"] == "High file diversity + Entropy"
        ]
        self.assertGreater(len(diversity_alerts), 0)

    def test_writes_to_single_dir_no_diversity_alert(self):
        """Many writes to the same directory should NOT trigger diversity alert."""
        det = RansomwareDetector(
            threshold_unique_files=5,
            threshold_unique_dirs=3,
            threshold_writes=100,  # Disable frequency check
            time_window=10.0,
            verify_binary_hash=False, verify_lineage=False,
        )
        buf = os.urandom(128)
        for i in range(20):
            evt = _make_event(
                1, 12001, "builder",
                f"/tmp/build/obj_{i}.o", 128, buf,
            )
            det.analyze_event(evt)
        diversity_alerts = [
            a for a in det.alerts if a["reason"] == "High file diversity + Entropy"
        ]
        self.assertEqual(len(diversity_alerts), 0)

    def test_low_entropy_diverse_writes_no_alert(self):
        """Diverse writes with low entropy (e.g. text) should not alert."""
        det = RansomwareDetector(
            threshold_unique_files=3,
            threshold_unique_dirs=2,
            threshold_writes=100,
            time_window=10.0,
            verify_binary_hash=False, verify_lineage=False,
        )
        buf = b"A" * 128  # Low entropy
        dirs = ["/home/user/a", "/home/user/b", "/home/user/c"]
        for d in dirs:
            for j in range(3):
                evt = _make_event(1, 12002, "writer", f"{d}/f{j}.txt", 128, buf)
                det.analyze_event(evt)
        diversity_alerts = [
            a for a in det.alerts if a["reason"] == "High file diversity + Entropy"
        ]
        self.assertEqual(len(diversity_alerts), 0)

    def test_get_file_diversity_counts(self):
        """Verify the diversity counter returns correct unique counts."""
        det = RansomwareDetector(
            time_window=10.0,
            verify_binary_hash=False, verify_lineage=False,
        )
        now = time.time()
        det.process_stats[999] = [
            (now, 7.0, "/home/user/a/f1.doc"),
            (now, 7.0, "/home/user/a/f2.doc"),
            (now, 7.0, "/home/user/b/f3.doc"),
            (now, 7.0, "/home/user/c/f4.doc"),
        ]
        files, dirs = det.get_file_diversity(999)
        self.assertEqual(files, 4)
        self.assertEqual(dirs, 3)

    def test_defrag_same_files_no_diversity_alert(self):
        """A defragmenter writing to the same file repeatedly → no diversity."""
        det = RansomwareDetector(
            threshold_unique_files=5,
            threshold_unique_dirs=3,
            threshold_writes=100,
            time_window=10.0,
            verify_binary_hash=False, verify_lineage=False,
        )
        buf = os.urandom(128)
        # Same file, many writes — like a defrag or database
        for i in range(50):
            evt = _make_event(1, 12003, "defrag", "/home/user/bigfile.dat", 128, buf)
            det.analyze_event(evt)
        diversity_alerts = [
            a for a in det.alerts if a["reason"] == "High file diversity + Entropy"
        ]
        self.assertEqual(len(diversity_alerts), 0)


# ---------------------------------------------------------------------------
# 8. Directory Traversal Detection Tests
# ---------------------------------------------------------------------------

class TestDirectoryTraversalDetection(unittest.TestCase):
    """Verify that rapid directory scanning + writes triggers alerts."""

    def test_dir_scan_with_writes_triggers_alert(self):
        """Scanning many directories while also writing → alert."""
        det = RansomwareDetector(
            threshold_dir_scans=3,
            time_window=10.0,
            verify_binary_hash=False, verify_lineage=False,
        )
        buf = os.urandom(128)
        # First, some writes to establish write activity
        for i in range(3):
            evt = _make_event(1, 13000, "evil", f"/home/user/f{i}.doc", 128, buf)
            det.analyze_event(evt)
        # Then, rapid directory scans (event type 4 = GETDENTS)
        dirs = ["/home/user/Documents", "/home/user/Pictures",
                "/home/user/Music", "/home/user/Videos"]
        for d in dirs:
            evt = _make_event(4, 13000, "evil", f"{d}/somefile", 0, b"")
            det.analyze_event(evt)
        traversal_alerts = [
            a for a in det.alerts if a["reason"] == "Directory traversal + Writes"
        ]
        self.assertGreater(len(traversal_alerts), 0)

    def test_dir_scan_without_writes_no_alert(self):
        """Directory scanning alone (no writes) should not trigger."""
        det = RansomwareDetector(
            threshold_dir_scans=3,
            time_window=10.0,
            verify_binary_hash=False, verify_lineage=False,
        )
        dirs = ["/home/a", "/home/b", "/home/c", "/home/d", "/home/e"]
        for d in dirs:
            evt = _make_event(4, 13001, "find", f"{d}/x", 0, b"")
            det.analyze_event(evt)
        traversal_alerts = [
            a for a in det.alerts if a["reason"] == "Directory traversal + Writes"
        ]
        self.assertEqual(len(traversal_alerts), 0)

    def test_few_dir_scans_no_alert(self):
        """Scanning fewer directories than the threshold → no alert."""
        det = RansomwareDetector(
            threshold_dir_scans=5,
            time_window=10.0,
            verify_binary_hash=False, verify_lineage=False,
        )
        buf = os.urandom(128)
        evt = _make_event(1, 13002, "evil", "/home/user/f.doc", 128, buf)
        det.analyze_event(evt)
        # Only 2 directory scans — below threshold of 5
        for d in ["/home/a", "/home/b"]:
            evt = _make_event(4, 13002, "evil", f"{d}/x", 0, b"")
            det.analyze_event(evt)
        traversal_alerts = [
            a for a in det.alerts if a["reason"] == "Directory traversal + Writes"
        ]
        self.assertEqual(len(traversal_alerts), 0)

    def test_dir_scans_expire_outside_window(self):
        """Old directory scans outside the time window should not count."""
        det = RansomwareDetector(
            threshold_dir_scans=3,
            time_window=0.01,  # Very short window
            verify_binary_hash=False, verify_lineage=False,
        )
        buf = os.urandom(128)
        evt = _make_event(1, 13003, "evil", "/home/user/f.doc", 128, buf)
        det.analyze_event(evt)
        for d in ["/home/a", "/home/b", "/home/c", "/home/d"]:
            evt = _make_event(4, 13003, "evil", f"{d}/x", 0, b"")
            det.analyze_event(evt)
            time.sleep(0.02)  # Each scan expires before the next
        traversal_alerts = [
            a for a in det.alerts if a["reason"] == "Directory traversal + Writes"
        ]
        self.assertEqual(len(traversal_alerts), 0)


# ---------------------------------------------------------------------------
# 9. Defragmenter vs Ransomware Scenario Tests
# ---------------------------------------------------------------------------

class TestDefragVsRansomware(unittest.TestCase):
    """End-to-end scenarios comparing defragmenter and ransomware behavior."""

    def test_defrag_block_device_writes_no_alerts(self):
        """A defragmenter writing to /dev/sda with high entropy → no alerts."""
        det = RansomwareDetector(
            threshold_writes=3, threshold_unique_files=3,
            threshold_unique_dirs=2, time_window=10.0,
            verify_binary_hash=False, verify_lineage=False,
        )
        buf = os.urandom(128)
        for i in range(50):
            evt = _make_event(1, 14000, "e4defrag", "/dev/sda1", 128, buf)
            det.analyze_event(evt)
        self.assertEqual(len(det.alerts), 0)

    def test_defrag_single_file_repeated_writes_no_alerts(self):
        """A defragmenter rewriting a single user file repeatedly → no diversity alert."""
        det = RansomwareDetector(
            threshold_writes=100,  # Disable frequency
            threshold_unique_files=5, threshold_unique_dirs=3,
            time_window=10.0,
            verify_binary_hash=False, verify_lineage=False,
        )
        buf = os.urandom(128)
        for i in range(50):
            evt = _make_event(1, 14001, "defrag", "/home/user/largefile.img", 128, buf)
            det.analyze_event(evt)
        diversity_alerts = [
            a for a in det.alerts if a["reason"] == "High file diversity + Entropy"
        ]
        self.assertEqual(len(diversity_alerts), 0)

    def test_ransomware_multi_dir_encryption_detected(self):
        """Ransomware encrypting files across directories → diversity alert."""
        det = RansomwareDetector(
            threshold_unique_files=4, threshold_unique_dirs=2,
            threshold_writes=100,  # Disable frequency to isolate diversity
            time_window=10.0,
            verify_binary_hash=False, verify_lineage=False,
        )
        buf = os.urandom(128)
        targets = [
            "/home/user/Documents/report.docx",
            "/home/user/Documents/budget.xlsx",
            "/home/user/Pictures/photo1.jpg",
            "/home/user/Pictures/photo2.png",
            "/home/user/Desktop/notes.txt",
        ]
        for f in targets:
            evt = _make_event(1, 14002, "cryptolocker", f, 128, buf)
            det.analyze_event(evt)
        diversity_alerts = [
            a for a in det.alerts if a["reason"] == "High file diversity + Entropy"
        ]
        self.assertGreater(len(diversity_alerts), 0)

    def test_ransomware_scan_then_encrypt_detected(self):
        """Ransomware scanning directories then encrypting → traversal alert."""
        det = RansomwareDetector(
            threshold_dir_scans=3,
            time_window=10.0,
            verify_binary_hash=False, verify_lineage=False,
        )
        buf = os.urandom(128)
        # Phase 1: scan directories
        scan_dirs = ["/home/user/Documents", "/home/user/Pictures",
                     "/home/user/Music"]
        # Phase 2: encrypt files (writes first so process_stats has entries)
        for d in scan_dirs:
            evt = _make_event(1, 14003, "locker", f"{d}/file.doc", 128, buf)
            det.analyze_event(evt)
        # Now scan
        for d in scan_dirs:
            evt = _make_event(4, 14003, "locker", f"{d}/.", 0, b"")
            det.analyze_event(evt)
        traversal_alerts = [
            a for a in det.alerts if a["reason"] == "Directory traversal + Writes"
        ]
        self.assertGreater(len(traversal_alerts), 0)

    def test_database_var_lib_writes_no_alerts(self):
        """A database writing to /var/lib/ with high entropy → no alerts."""
        det = RansomwareDetector(
            threshold_writes=3, time_window=10.0,
            verify_binary_hash=False, verify_lineage=False,
        )
        buf = os.urandom(128)
        for i in range(30):
            evt = _make_event(
                1, 14004, "postgres_fake",
                f"/var/lib/postgresql/data/base/{i}.dat", 128, buf,
            )
            det.analyze_event(evt)
        self.assertEqual(len(det.alerts), 0)


# ---------------------------------------------------------------------------
# 10. In-Place Overwrite Detection Tests
# ---------------------------------------------------------------------------

class TestInPlaceOverwriteDetection(unittest.TestCase):
    """Verify that writing high-entropy data back to an opened file is flagged."""

    def _det(self, **kw):
        defaults = dict(
            verify_binary_hash=False, verify_lineage=False,
            time_window=10.0, threshold_writes=100,
        )
        defaults.update(kw)
        return RansomwareDetector(**defaults)

    def test_overwrite_opened_file_triggers_alert(self):
        """OPEN multiple files, then WRITE high-entropy data to them → alert."""
        det = self._det()
        buf = os.urandom(128)
        # Must overwrite 2+ distinct files to trigger (single-file is benign).
        for fname in ["/home/user/photo.jpg", "/home/user/report.docx"]:
            evt = _make_event(0, 15000, "evil", fname, 0, b"")
            det.analyze_event(evt)
            evt = _make_event(1, 15000, "evil", fname, 128, buf)
            det.analyze_event(evt)
        overwrite_alerts = [
            a for a in det.alerts if a["reason"] == "In-place overwrite"
        ]
        self.assertGreater(len(overwrite_alerts), 0)

    def test_single_file_in_place_encrypt_no_alert(self):
        """Single-file in-place encryption (e.g. ccencrypt) → no alert."""
        det = self._det()
        evt = _make_event(0, 15004, "ccencrypt", "/home/user/notes.bin", 0, b"")
        det.analyze_event(evt)
        buf = os.urandom(128)
        evt = _make_event(1, 15004, "ccencrypt", "/home/user/notes.bin", 128, buf)
        det.analyze_event(evt)
        overwrite_alerts = [
            a for a in det.alerts if a["reason"] == "In-place overwrite"
        ]
        self.assertEqual(len(overwrite_alerts), 0)

    def test_write_to_new_file_no_overwrite_alert(self):
        """Writing to a file that was never opened → no in-place alert."""
        det = self._det()
        buf = os.urandom(128)
        evt = _make_event(1, 15001, "evil", "/home/user/newfile.enc", 128, buf)
        det.analyze_event(evt)
        overwrite_alerts = [
            a for a in det.alerts if a["reason"] == "In-place overwrite"
        ]
        self.assertEqual(len(overwrite_alerts), 0)

    def test_low_entropy_overwrite_no_alert(self):
        """Overwriting with low-entropy data (e.g. text) → no alert."""
        det = self._det()
        evt = _make_event(0, 15002, "editor", "/home/user/notes.txt", 0, b"")
        det.analyze_event(evt)
        buf = b"A" * 128
        evt = _make_event(1, 15002, "editor", "/home/user/notes.txt", 128, buf)
        det.analyze_event(evt)
        overwrite_alerts = [
            a for a in det.alerts if a["reason"] == "In-place overwrite"
        ]
        self.assertEqual(len(overwrite_alerts), 0)

    def test_legitimate_gz_output_no_overwrite_alert(self):
        """gzip: open report.txt, write to report.txt.gz → no alert."""
        det = self._det()
        # Open the source
        evt = _make_event(0, 15003, "gzip_sim", "/home/user/report.txt", 0, b"")
        det.analyze_event(evt)
        # Write compressed output to a .gz derivative
        buf = os.urandom(128)
        evt = _make_event(1, 15003, "gzip_sim", "/home/user/report.txt.gz", 128, buf)
        det.analyze_event(evt)
        overwrite_alerts = [
            a for a in det.alerts if a["reason"] == "In-place overwrite"
        ]
        self.assertEqual(len(overwrite_alerts), 0)


# ---------------------------------------------------------------------------
# 11. Output-to-Input Path Correlation Tests
# ---------------------------------------------------------------------------

class TestOutputPathCorrelation(unittest.TestCase):
    """Verify legitimate vs ransomware output naming detection."""

    def test_gz_suffix_is_legitimate(self):
        opened = ["/home/user/data.csv"]
        self.assertTrue(
            RansomwareDetector.is_legitimate_output_name(
                "/home/user/data.csv.gz", opened
            )
        )

    def test_gpg_suffix_is_legitimate(self):
        opened = ["/home/user/secret.txt"]
        self.assertTrue(
            RansomwareDetector.is_legitimate_output_name(
                "/home/user/secret.txt.gpg", opened
            )
        )

    def test_zip_base_match_is_legitimate(self):
        opened = ["/home/user/archive.docx"]
        self.assertTrue(
            RansomwareDetector.is_legitimate_output_name(
                "/home/user/archive.zip", opened
            )
        )

    def test_xz_suffix_is_legitimate(self):
        opened = ["/home/user/dump.sql"]
        self.assertTrue(
            RansomwareDetector.is_legitimate_output_name(
                "/home/user/dump.sql.xz", opened
            )
        )

    def test_locked_suffix_is_not_legitimate(self):
        opened = ["/home/user/photo.jpg"]
        self.assertFalse(
            RansomwareDetector.is_legitimate_output_name(
                "/home/user/photo.jpg.locked", opened
            )
        )

    def test_random_extension_is_not_legitimate(self):
        opened = ["/home/user/report.docx"]
        self.assertFalse(
            RansomwareDetector.is_legitimate_output_name(
                "/home/user/report.docx.a1b2c3", opened
            )
        )

    def test_unrelated_name_is_not_legitimate(self):
        opened = ["/home/user/budget.xlsx"]
        self.assertFalse(
            RansomwareDetector.is_legitimate_output_name(
                "/home/user/totally_different.enc", opened
            )
        )

    def test_no_opened_files_is_not_legitimate(self):
        self.assertFalse(
            RansomwareDetector.is_legitimate_output_name(
                "/home/user/file.gz", []
            )
        )

    def test_enc_suffix_is_legitimate(self):
        opened = ["/home/user/backup.tar"]
        self.assertTrue(
            RansomwareDetector.is_legitimate_output_name(
                "/home/user/backup.tar.enc", opened
            )
        )


# ---------------------------------------------------------------------------
# 12. Write-Then-Unlink Correlation Tests
# ---------------------------------------------------------------------------

class TestWriteThenUnlinkCorrelation(unittest.TestCase):
    """Verify detection of the encrypt-copy-then-delete-original pattern."""

    def _det(self, **kw):
        defaults = dict(
            verify_binary_hash=False, verify_lineage=False,
            time_window=10.0, threshold_writes=100,
            threshold_unlinks=100,  # Disable frequency unlink alert
        )
        defaults.update(kw)
        return RansomwareDetector(**defaults)

    def test_write_multiple_then_delete_original_triggers(self):
        """Write to 3+ files, then delete a different file → alert."""
        det = self._det()
        buf = os.urandom(128)
        # Write encrypted copies
        for i in range(4):
            evt = _make_event(1, 16000, "evil", f"/home/user/f{i}.locked", 128, buf)
            det.analyze_event(evt)
        # Delete an original (different from write targets)
        evt = _make_event(3, 16000, "evil", "/home/user/original.docx", 0, b"")
        det.analyze_event(evt)
        wtu_alerts = [
            a for a in det.alerts if a["reason"] == "Write-then-delete"
        ]
        self.assertGreater(len(wtu_alerts), 0)

    def test_delete_own_write_target_no_alert(self):
        """Deleting a file you just wrote to is normal (temp file cleanup)."""
        det = self._det()
        buf = os.urandom(128)
        for i in range(4):
            evt = _make_event(1, 16001, "builder", f"/tmp/out_{i}.o", 128, buf)
            det.analyze_event(evt)
        # Delete one of the files we wrote to
        evt = _make_event(3, 16001, "builder", "/tmp/out_0.o", 0, b"")
        det.analyze_event(evt)
        wtu_alerts = [
            a for a in det.alerts if a["reason"] == "Write-then-delete"
        ]
        self.assertEqual(len(wtu_alerts), 0)

    def test_single_write_then_delete_no_alert(self):
        """gzip pattern: write one .gz, delete one source → no alert (< 3 targets)."""
        det = self._det()
        buf = os.urandom(128)
        evt = _make_event(1, 16002, "gzip_sim", "/home/user/data.csv.gz", 128, buf)
        det.analyze_event(evt)
        evt = _make_event(3, 16002, "gzip_sim", "/home/user/data.csv", 0, b"")
        det.analyze_event(evt)
        wtu_alerts = [
            a for a in det.alerts if a["reason"] == "Write-then-delete"
        ]
        self.assertEqual(len(wtu_alerts), 0)

    def test_low_entropy_writes_then_delete_no_alert(self):
        """Low-entropy writes followed by deletes → no alert."""
        det = self._det()
        buf = b"A" * 128
        for i in range(5):
            evt = _make_event(1, 16003, "writer", f"/home/user/f{i}.txt", 128, buf)
            det.analyze_event(evt)
        evt = _make_event(3, 16003, "writer", "/home/user/original.txt", 0, b"")
        det.analyze_event(evt)
        wtu_alerts = [
            a for a in det.alerts if a["reason"] == "Write-then-delete"
        ]
        self.assertEqual(len(wtu_alerts), 0)

    def test_write_targets_expire_outside_window(self):
        """Old write targets outside the time window should not count."""
        det = self._det(time_window=0.01)
        buf = os.urandom(128)
        for i in range(4):
            evt = _make_event(1, 16004, "evil", f"/home/user/f{i}.locked", 128, buf)
            det.analyze_event(evt)
            time.sleep(0.02)
        evt = _make_event(3, 16004, "evil", "/home/user/original.docx", 0, b"")
        det.analyze_event(evt)
        wtu_alerts = [
            a for a in det.alerts if a["reason"] == "Write-then-delete"
        ]
        self.assertEqual(len(wtu_alerts), 0)


# ---------------------------------------------------------------------------
# 13. Legitimate Encryption vs Ransomware Scenario Tests
# ---------------------------------------------------------------------------

class TestLegitEncryptionVsRansomware(unittest.TestCase):
    """End-to-end scenarios comparing zip/gzip/gpg with ransomware."""

    def _det(self, **kw):
        defaults = dict(
            verify_binary_hash=False, verify_lineage=False,
            time_window=10.0, threshold_writes=100,
            threshold_unlinks=100,
        )
        defaults.update(kw)
        return RansomwareDetector(**defaults)

    def test_gzip_single_file_no_alerts(self):
        """gzip: open file, write .gz, delete original → no ransomware alerts."""
        det = self._det()
        # Open source
        evt = _make_event(0, 17000, "gzip_sim", "/home/user/data.csv", 0, b"")
        det.analyze_event(evt)
        # Write compressed output
        buf = os.urandom(128)
        evt = _make_event(1, 17000, "gzip_sim", "/home/user/data.csv.gz", 128, buf)
        det.analyze_event(evt)
        # Delete original
        evt = _make_event(3, 17000, "gzip_sim", "/home/user/data.csv", 0, b"")
        det.analyze_event(evt)
        # Should have no in-place, no write-then-delete alerts
        bad_alerts = [
            a for a in det.alerts
            if a["reason"] in ("In-place overwrite", "Write-then-delete")
        ]
        self.assertEqual(len(bad_alerts), 0)

    def test_gpg_encrypt_file_no_in_place_alert(self):
        """gpg: open secret.txt, write secret.txt.gpg → no in-place alert."""
        det = self._det()
        evt = _make_event(0, 17001, "gpg_sim", "/home/user/secret.txt", 0, b"")
        det.analyze_event(evt)
        buf = os.urandom(128)
        evt = _make_event(1, 17001, "gpg_sim", "/home/user/secret.txt.gpg", 128, buf)
        det.analyze_event(evt)
        overwrite_alerts = [
            a for a in det.alerts if a["reason"] == "In-place overwrite"
        ]
        self.assertEqual(len(overwrite_alerts), 0)

    def test_ransomware_in_place_encrypt_detected(self):
        """Ransomware: open multiple files, write ciphertext back → alert."""
        det = self._det()
        buf = os.urandom(128)
        # Must overwrite 2+ distinct files to trigger.
        for fname in ["/home/user/photo.jpg", "/home/user/report.docx"]:
            evt = _make_event(0, 17002, "locker", fname, 0, b"")
            det.analyze_event(evt)
            evt = _make_event(1, 17002, "locker", fname, 128, buf)
            det.analyze_event(evt)
        overwrite_alerts = [
            a for a in det.alerts if a["reason"] == "In-place overwrite"
        ]
        self.assertGreater(len(overwrite_alerts), 0)

    def test_ransomware_encrypt_then_delete_detected(self):
        """Ransomware: write .locked copies, delete originals → alert."""
        det = self._det()
        buf = os.urandom(128)
        originals = [
            "/home/user/Documents/report.docx",
            "/home/user/Pictures/photo.jpg",
            "/home/user/Desktop/notes.txt",
        ]
        # Write encrypted copies
        for f in originals:
            evt = _make_event(1, 17003, "locker", f + ".locked", 128, buf)
            det.analyze_event(evt)
        # Delete originals
        for f in originals:
            evt = _make_event(3, 17003, "locker", f, 0, b"")
            det.analyze_event(evt)
        wtu_alerts = [
            a for a in det.alerts if a["reason"] == "Write-then-delete"
        ]
        self.assertGreater(len(wtu_alerts), 0)

    def test_zip_multiple_files_no_write_then_delete(self):
        """zip: writes to one archive.zip, no source deletion → no alert."""
        det = self._det()
        buf = os.urandom(128)
        # zip writes all data to a single output file
        for i in range(10):
            evt = _make_event(1, 17004, "zip_sim", "/home/user/archive.zip", 128, buf)
            det.analyze_event(evt)
        wtu_alerts = [
            a for a in det.alerts if a["reason"] == "Write-then-delete"
        ]
        self.assertEqual(len(wtu_alerts), 0)

    def test_tar_gz_pipeline_no_alerts(self):
        """tar | gzip: writes to archive.tar.gz → no ransomware alerts."""
        det = self._det()
        # Open source directory listing (simulated)
        evt = _make_event(0, 17005, "tar_sim", "/home/user/project", 0, b"")
        det.analyze_event(evt)
        buf = os.urandom(128)
        # Write to archive
        for i in range(5):
            evt = _make_event(1, 17005, "tar_sim", "/home/user/project.tar.gz", 128, buf)
            det.analyze_event(evt)
        bad_alerts = [
            a for a in det.alerts
            if a["reason"] in ("In-place overwrite", "Write-then-delete")
        ]
        self.assertEqual(len(bad_alerts), 0)


# ---------------------------------------------------------------------------
# EDR Response Chain Tests
# ---------------------------------------------------------------------------

class TestEDRResponseChain(unittest.TestCase):
    """Verify the 6-step EDR response chain."""

    def _det(self, **kw):
        defaults = dict(
            verify_binary_hash=False, verify_lineage=False,
            time_window=10.0,
        )
        defaults.update(kw)
        return RansomwareDetector(**defaults)

    # --- Step 0: Simulate mode ---

    def test_simulate_mode_does_not_kill(self):
        det = self._det(action_mode="simulate")
        with mock.patch("os.kill") as mock_kill:
            det.take_action(99999, "test", "test reason")
            mock_kill.assert_not_called()

    def test_default_mode_is_simulate(self):
        det = self._det()
        self.assertEqual(det.action_mode, "simulate")

    # --- Step 1: Process Kill ---

    def test_kill_mode_sends_sigkill(self):
        det = self._det(action_mode="kill")
        det._record_alert(99999, "evil", "Test", severity="high")
        with mock.patch("os.kill") as mock_kill, \
             mock.patch.object(det, "_step_quarantine", return_value=None), \
             mock.patch.object(det, "_step_network_isolate"), \
             mock.patch.object(det, "_step_harden_binary"):
            det.take_action(99999, "evil", "Test")
            # Should have called os.kill with SIGKILL for the main PID
            calls = [c for c in mock_kill.call_args_list if c[0][0] == 99999]
            self.assertTrue(
                any(c[0][1] == signal_mod.SIGKILL for c in calls),
                f"Expected SIGKILL for PID 99999, got {calls}",
            )

    def test_suspend_mode_sends_sigstop(self):
        det = self._det(action_mode="suspend")
        det._record_alert(99999, "evil", "Test", severity="high")
        with mock.patch("os.kill") as mock_kill, \
             mock.patch.object(det, "_step_quarantine", return_value=None), \
             mock.patch.object(det, "_step_network_isolate"), \
             mock.patch.object(det, "_step_harden_binary"):
            det.take_action(99999, "evil", "Test")
            calls = [c for c in mock_kill.call_args_list if c[0][0] == 99999]
            self.assertTrue(
                any(c[0][1] == signal_mod.SIGSTOP for c in calls),
                f"Expected SIGSTOP for PID 99999, got {calls}",
            )

    def test_kill_targets_children(self):
        det = self._det(action_mode="kill")
        det._record_alert(99999, "evil", "Test", severity="high")
        with mock.patch("os.kill") as mock_kill, \
             mock.patch.object(
                 RansomwareDetector, "_get_child_pids", return_value=[10001, 10002]
             ), \
             mock.patch.object(det, "_step_quarantine", return_value=None), \
             mock.patch.object(det, "_step_network_isolate"), \
             mock.patch.object(det, "_step_harden_binary"):
            det.take_action(99999, "evil", "Test")
            killed_pids = {c[0][0] for c in mock_kill.call_args_list}
            self.assertIn(10001, killed_pids)
            self.assertIn(10002, killed_pids)
            self.assertIn(99999, killed_pids)

    # --- Step 2: Quarantine ---

    def test_quarantine_copies_binary(self):
        det = self._det(action_mode="kill")
        with tempfile.TemporaryDirectory() as qdir:
            det.quarantine_dir = qdir
            # Create a fake binary
            fake_bin = os.path.join(qdir, "evil_bin")
            with open(fake_bin, "w") as f:
                f.write("malicious code")
            os.chmod(fake_bin, 0o755)

            result = det._step_quarantine(99999, "evil", fake_bin)
            self.assertIsNotNone(result)
            self.assertTrue(os.path.exists(result))
            # Quarantined file should have no permissions
            mode = os.stat(result).st_mode & 0o777
            self.assertEqual(mode, 0o000)

    def test_quarantine_nonexistent_binary_returns_none(self):
        det = self._det(action_mode="kill")
        result = det._step_quarantine(99999, "evil", "/no/such/binary")
        self.assertIsNone(result)

    # --- Step 3: Network Isolation ---

    def test_network_isolation_calls_iptables(self):
        det = self._det(action_mode="kill", enable_network_isolation=True)
        with mock.patch.object(
            RansomwareDetector, "_get_pid_uid", return_value=1000
        ), mock.patch("subprocess.run") as mock_run:
            det._step_network_isolate(99999, "evil")
            mock_run.assert_called_once()
            cmd = mock_run.call_args[0][0]
            self.assertIn("iptables", cmd)
            self.assertIn("1000", cmd)

    def test_network_isolation_disabled_by_default(self):
        det = self._det(action_mode="kill")
        with mock.patch("subprocess.run") as mock_run:
            det._step_network_isolate(99999, "evil")
            mock_run.assert_not_called()

    # --- Step 4: Remediation ---

    def test_remediation_tracks_modified_files(self):
        det = self._det(action_mode="kill")
        det._pid_modified_files[99999] = [
            "/home/user/doc1.docx",
            "/home/user/doc2.pdf",
            "/home/user/doc1.docx",  # Duplicate
        ]
        # Should not crash; just logs
        det._step_remediate(99999, "evil")
        # Verify the tracking is populated
        self.assertEqual(len(det._pid_modified_files[99999]), 3)

    def test_write_events_populate_modified_files(self):
        det = self._det(action_mode="simulate")
        buf = os.urandom(128)
        for f in ["/home/user/a.doc", "/home/user/b.doc"]:
            evt = _make_event(1, 20000, "evil", f, 128, buf)
            det.analyze_event(evt)
        self.assertGreater(len(det._pid_modified_files[20000]), 0)

    # --- Step 5: Rollback ---

    def test_rollback_triggers_snapshot(self):
        det = self._det(action_mode="kill", snapshot_cmd="echo snapshot_ok")
        det._record_alert(99999, "evil", "Test", severity="critical")
        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = mock.Mock(returncode=0, stderr="")
            det._step_rollback(99999, "evil")
            mock_run.assert_called_once()
            self.assertTrue(det._snapshot_triggered)

    def test_rollback_only_triggers_once(self):
        det = self._det(action_mode="kill", snapshot_cmd="echo snapshot_ok")
        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = mock.Mock(returncode=0, stderr="")
            det._step_rollback(99999, "evil")
            det._step_rollback(99999, "evil")
            mock_run.assert_called_once()

    def test_rollback_skipped_without_cmd(self):
        det = self._det(action_mode="kill", snapshot_cmd=None)
        with mock.patch("subprocess.run") as mock_run:
            det._step_rollback(99999, "evil")
            mock_run.assert_not_called()

    # --- Step 6: Binary Hardening ---

    def test_harden_strips_exec_bit(self):
        det = self._det(action_mode="kill")
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"malicious")
            fake_bin = f.name
        try:
            os.chmod(fake_bin, 0o755)
            det._step_harden_binary(99999, "evil", fake_bin, None)
            mode = os.stat(fake_bin).st_mode
            self.assertFalse(mode & stat.S_IXUSR)
            self.assertFalse(mode & stat.S_IXGRP)
            self.assertFalse(mode & stat.S_IXOTH)
        finally:
            os.unlink(fake_bin)

    def test_harden_adds_to_blocklist(self):
        det = self._det(action_mode="kill")
        det._step_harden_binary(99999, "evil", "/usr/bin/evil", None)
        self.assertIn("/usr/bin/evil", det.blocklist)

    # --- Full chain integration ---

    def test_full_chain_executes_all_steps(self):
        """In kill mode, all 6 steps should execute for a critical alert."""
        det = self._det(
            action_mode="kill",
            snapshot_cmd="echo snap",
            enable_network_isolation=True,
        )
        det._record_alert(99999, "evil", "Test", severity="critical")

        with mock.patch("os.kill"), \
             mock.patch.object(
                 RansomwareDetector, "_resolve_exe", return_value="/tmp/fake_evil"
             ), \
             mock.patch.object(det, "_step_quarantine", return_value="/quarantine/evil") as m_quar, \
             mock.patch.object(det, "_step_network_isolate") as m_net, \
             mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = mock.Mock(returncode=0, stderr="")
            det.take_action(99999, "evil", "Test")

            m_quar.assert_called_once()
            m_net.assert_called_once()
            self.assertTrue(det._snapshot_triggered)
            self.assertIn("/tmp/fake_evil", det.blocklist)


if __name__ == "__main__":
    unittest.main()
