import os
import sys

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
# 1e. Process-Tree Attribution Tests
# ---------------------------------------------------------------------------

class TestProcessTreeAttribution(unittest.TestCase):
    """Verify that trusted child writes can be attributed to a parent."""

    def test_whitelisted_child_writes_attributed_to_parent(self):
        """High-entropy child writes should lift the active parent profile."""
        det = RansomwareDetector(
            threshold_entropy=5.0,
            threshold_unique_files=3,
            threshold_unique_dirs=2,
            threshold_dir_scans=3,
            threshold_writes=100,  # isolate the diversity heuristic
            time_window=10.0,
            verify_binary_hash=False,
            verify_lineage=False,
        )
        buf = os.urandom(128)
        parent_pid = 20000
        child_pid = 20001
        dirs = [
            "/home/user/Documents",
            "/home/user/Pictures",
            "/home/user/Desktop",
        ]

        # Parent establishes an active profile via directory traversal.
        for directory in dirs:
            evt = make_event(4, parent_pid, b"ransim_dlg\x00", f"{directory}/.", 0, b"")
            det.analyze_event(evt)

        with mock.patch.object(det, "get_parent_pid", return_value=parent_pid), \
             mock.patch.object(det, "_read_proc_comm", return_value="ransim_dlg"):
            for i, directory in enumerate(dirs):
                evt = make_event(
                    1,
                    child_pid,
                    b"ccencrypt\x00\x00",
                    f"{directory}/file_{i}.cpt",
                    128,
                    buf,
                )
                det.analyze_event(evt)

        parent_alerts = [a for a in det.alerts if a["pid"] == parent_pid]
        self.assertGreater(len(parent_alerts), 0)
        self.assertTrue(any(a.get("attributed") for a in parent_alerts))
        self.assertTrue(
            any(a.get("attributed_from_comm") == "ccencrypt" for a in parent_alerts)
        )
        self.assertTrue(any(a.get("armed_by_traversal") for a in parent_alerts))
        self.assertEqual(len([a for a in det.alerts if a["pid"] == child_pid]), 0)

    def test_bpf_provided_ppid_avoids_short_lived_child_race(self):
        """The child->parent hop should work from event.ppid without /proc lookup."""
        det = RansomwareDetector(
            threshold_entropy=5.0,
            threshold_unique_files=3,
            threshold_unique_dirs=2,
            threshold_dir_scans=3,
            threshold_writes=100,
            time_window=10.0,
            verify_binary_hash=False,
            verify_lineage=False,
        )
        buf = os.urandom(128)
        parent_pid = 20500
        child_pid = 20501
        dirs = [
            "/home/user/Documents",
            "/home/user/Pictures",
            "/home/user/Desktop",
        ]

        for directory in dirs:
            det.analyze_event(
                make_event(4, parent_pid, b"ransim_dlg\x00", f"{directory}/.", 0, b"")
            )

        with mock.patch.object(
            det,
            "get_parent_pid",
            side_effect=AssertionError("child /proc lookup should not be needed"),
        ), mock.patch.object(det, "_read_proc_comm", return_value="ransim_dlg"):
            for i, directory in enumerate(dirs):
                det.analyze_event(
                    make_event(
                        1,
                        child_pid,
                        b"ccencrypt\x00\x00",
                        f"{directory}/file_{i}.cpt",
                        128,
                        buf,
                        ppid=parent_pid,
                    )
                )

        parent_alerts = [a for a in det.alerts if a["pid"] == parent_pid]
        self.assertGreater(len(parent_alerts), 0)
        self.assertTrue(any(a.get("attributed") for a in parent_alerts))

    def test_whitelisted_helper_non_write_events_stay_suppressed_under_parent(self):
        """A delegated helper should not emit its own lineage alert once attributed."""
        det = RansomwareDetector(
            threshold_entropy=5.0,
            threshold_unique_files=3,
            threshold_unique_dirs=2,
            threshold_dir_scans=3,
            threshold_writes=100,
            time_window=10.0,
            verify_binary_hash=False,
            verify_lineage=True,
        )
        parent_pid = 20600
        child_pid = 20601

        for directory in (
            "/home/user/Documents",
            "/home/user/Pictures",
            "/home/user/Desktop",
        ):
            det.analyze_event(
                make_event(4, parent_pid, b"ransim_dlg\x00", f"{directory}/.", 0, b"")
            )

        with mock.patch.object(det, "_read_proc_comm", return_value="ransim_dlg"):
            det.analyze_event(
                make_event(
                    0,
                    child_pid,
                    b"ccencrypt\x00\x00",
                    "/home/user/Documents/report.docx.cpt",
                    0,
                    b"",
                    ppid=parent_pid,
                )
            )

        child_alerts = [a for a in det.alerts if a["pid"] == child_pid]
        self.assertEqual(child_alerts, [])

    def test_whitelisted_child_no_attribution_when_parent_whitelisted(self):
        """Benign helper processes should stay silent under trusted parents."""
        det = RansomwareDetector(
            threshold_writes=3,
            time_window=10.0,
            verify_binary_hash=False,
            verify_lineage=False,
        )
        buf = os.urandom(128)
        child_pid = 21001

        with mock.patch.object(det, "get_parent_pid", return_value=21000), \
             mock.patch.object(det, "_read_proc_comm", return_value="bash"):
            for i in range(10):
                evt = make_event(
                    1,
                    child_pid,
                    b"gzip\x00\x00",
                    f"/home/user/file_{i}.gz",
                    128,
                    buf,
                )
                det.analyze_event(evt)

        self.assertEqual(len(det.alerts), 0)

    def test_no_attribution_when_parent_has_no_active_signals(self):
        """A parent without recent behavioral state should not inherit writes."""
        det = RansomwareDetector(
            threshold_writes=3,
            time_window=10.0,
            verify_binary_hash=False,
            verify_lineage=False,
        )
        buf = os.urandom(128)
        parent_pid = 22000
        child_pid = 22001

        with mock.patch.object(det, "get_parent_pid", return_value=parent_pid), \
             mock.patch.object(det, "_read_proc_comm", return_value="unknown_proc"):
            for i in range(10):
                evt = make_event(
                    1,
                    child_pid,
                    b"ccencrypt\x00\x00",
                    f"/home/user/file_{i}.cpt",
                    128,
                    buf,
                )
                det.analyze_event(evt)

        self.assertEqual(len(det.alerts), 0)

    def test_whitelisted_same_pid_exec_does_not_inherit_shell_identity(self):
        """A shell exec into a trusted tool should not attribute back to the shell PID."""
        det = RansomwareDetector(
            threshold_entropy=5.0,
            threshold_unique_files=3,
            threshold_unique_dirs=2,
            threshold_dir_scans=3,
            threshold_writes=100,
            time_window=10.0,
            verify_binary_hash=False,
            verify_lineage=False,
        )
        pid = 23001
        buf = os.urandom(128)
        dirs = [
            "/home/user/Documents",
            "/home/user/Pictures",
            "/home/user/Desktop",
        ]

        for directory in dirs:
            evt = make_event(4, pid, b"ransim_dlg\x00", f"{directory}/.", 0, b"")
            det.analyze_event(evt)

        for i, directory in enumerate(dirs):
            evt = make_event(
                1,
                pid,
                b"gzip\x00\x00",
                f"{directory}/file_{i}.cpt",
                128,
                buf,
            )
            det.analyze_event(evt)

        alerts = [a for a in det.alerts if a["pid"] == pid]
        self.assertEqual(alerts, [])

    def test_fork_exec_helper_aggregates_writes_back_to_parent(self):
        """Fresh helper PIDs should roll their inherited identity back to the parent."""
        det = RansomwareDetector(
            threshold_entropy=5.0,
            threshold_unique_files=3,
            threshold_unique_dirs=2,
            threshold_dir_scans=3,
            threshold_writes=100,
            time_window=10.0,
            verify_binary_hash=False,
            verify_lineage=False,
        )
        parent_pid = 24000
        child_pids = [24001, 24002, 24003]
        buf = os.urandom(128)
        dirs = [
            "/home/user/Documents",
            "/home/user/Pictures",
            "/home/user/Desktop",
        ]

        parent_lookup = {child: parent_pid for child in child_pids}

        with mock.patch.object(det, "get_parent_pid", side_effect=lambda pid: parent_lookup.get(pid)), \
             mock.patch.object(det, "_read_proc_comm", return_value="ransim_dlg"):
            for child_pid, directory in zip(child_pids, dirs):
                det.analyze_event(
                    make_event(4, child_pid, b"ransim_dlg\x00", f"{directory}/.", 0, b"")
                )
                det.analyze_event(
                    make_event(
                        1,
                        child_pid,
                        b"ccencrypt\x00\x00",
                        f"{directory}/file.cpt",
                        128,
                        buf,
                    )
                )

        parent_alerts = [a for a in det.alerts if a["pid"] == parent_pid]
        self.assertGreater(len(parent_alerts), 0)
        self.assertTrue(any(a.get("attribution_mode") == "process_tree" for a in parent_alerts))

    def test_non_whitelisted_child_writes_are_not_attributed_by_default(self):
        """Without the experimental flag, non-whitelisted helpers stay per-PID."""
        det = RansomwareDetector(
            threshold_entropy=5.0,
            threshold_unique_files=3,
            threshold_unique_dirs=2,
            threshold_writes=100,
            time_window=10.0,
            verify_binary_hash=False,
            verify_lineage=False,
        )
        buf = os.urandom(128)
        parent_pid = 25000
        child_pid = 25001
        dirs = [
            "/home/user/Documents",
            "/home/user/Pictures",
            "/home/user/Desktop",
        ]

        for directory in dirs:
            det.analyze_event(
                make_event(4, parent_pid, b"ransim_dlg\x00", f"{directory}/.", 0, b"")
            )

        with mock.patch.object(det, "_read_proc_comm", return_value="ransim_dlg"):
            for i, directory in enumerate(dirs):
                det.analyze_event(
                    make_event(
                        1,
                        child_pid,
                        b"customcrypt\x00",
                        f"{directory}/file_{i}.enc",
                        128,
                        buf,
                        ppid=parent_pid,
                    )
                )

        parent_alerts = [a for a in det.alerts if a["pid"] == parent_pid]
        child_alerts = [a for a in det.alerts if a["pid"] == child_pid]
        self.assertEqual(parent_alerts, [])
        self.assertGreater(len(child_alerts), 0)
        self.assertFalse(any(a.get("attributed") for a in child_alerts))

    def test_non_whitelisted_child_writes_are_attributed_when_enabled(self):
        """Experimental mode should alert on both the helper and orchestrator."""
        det = RansomwareDetector(
            threshold_entropy=5.0,
            threshold_unique_files=3,
            threshold_unique_dirs=2,
            threshold_dir_scans=3,
            threshold_writes=100,
            time_window=10.0,
            verify_binary_hash=False,
            verify_lineage=False,
            attribute_all_child_writes=True,
        )
        buf = os.urandom(128)
        parent_pid = 25100
        child_pid = 25101
        dirs = [
            "/home/user/Documents",
            "/home/user/Pictures",
            "/home/user/Desktop",
        ]

        for directory in dirs:
            det.analyze_event(
                make_event(4, parent_pid, b"ransim_dlg\x00", f"{directory}/.", 0, b"")
            )

        with mock.patch.object(det, "_read_proc_comm", return_value="ransim_dlg"):
            for i, directory in enumerate(dirs):
                det.analyze_event(
                    make_event(
                        1,
                        child_pid,
                        b"customcrypt\x00",
                        f"{directory}/file_{i}.enc",
                        128,
                        buf,
                        ppid=parent_pid,
                    )
                )

        parent_alerts = [a for a in det.alerts if a["pid"] == parent_pid]
        child_alerts = [a for a in det.alerts if a["pid"] == child_pid]
        self.assertGreater(len(parent_alerts), 0)
        self.assertGreater(len(child_alerts), 0)
        self.assertTrue(any(a.get("attributed") for a in parent_alerts))
        self.assertTrue(
            any(a.get("attributed_from_comm") == "customcrypt" for a in parent_alerts)
        )
        self.assertTrue(any(a.get("armed_by_traversal") for a in parent_alerts))

    def test_generic_launcher_needs_stronger_context_for_child_attribution(self):
        """A generic shell parent should not inherit child writes on weak scan context."""
        det = RansomwareDetector(
            threshold_entropy=5.0,
            threshold_unique_files=3,
            threshold_unique_dirs=2,
            threshold_dir_scans=3,
            threshold_writes=100,
            time_window=10.0,
            verify_binary_hash=False,
            verify_lineage=False,
            attribute_all_child_writes=True,
        )
        buf = os.urandom(128)
        parent_pid = 25200
        child_pid = 25201
        dirs = [
            "/home/user/Documents",
            "/home/user/Pictures",
            "/home/user/Desktop",
        ]

        for directory in dirs:
            det.analyze_event(
                make_event(4, parent_pid, b"bash\x00", f"{directory}/.", 0, b"")
            )

        with mock.patch.object(det, "_read_proc_comm", return_value="bash"):
            for i, directory in enumerate(dirs):
                det.analyze_event(
                    make_event(
                        1,
                        child_pid,
                        b"dd\x00",
                        f"{directory}/sample_{i}.bin",
                        128,
                        buf,
                        ppid=parent_pid,
                    )
                )

        parent_alerts = [a for a in det.alerts if a["pid"] == parent_pid]
        self.assertEqual(parent_alerts, [])

    def test_child_write_outside_parent_scanned_paths_is_not_attributed(self):
        """A child write outside the parent's scanned tree should stay per-PID."""
        det = RansomwareDetector(
            threshold_entropy=5.0,
            threshold_unique_files=3,
            threshold_unique_dirs=2,
            threshold_dir_scans=3,
            threshold_writes=100,
            time_window=10.0,
            verify_binary_hash=False,
            verify_lineage=False,
            attribute_all_child_writes=True,
        )
        buf = os.urandom(128)
        parent_pid = 25300
        child_pid = 25301
        dirs = [
            "/home/user/Documents",
            "/home/user/Pictures",
            "/home/user/Desktop",
        ]

        for directory in dirs:
            det.analyze_event(
                make_event(4, parent_pid, b"ransim_dlg\x00", f"{directory}/.", 0, b"")
            )

        with mock.patch.object(det, "_read_proc_comm", return_value="ransim_dlg"):
            for i in range(3):
                det.analyze_event(
                    make_event(
                        1,
                        child_pid,
                        b"customcrypt\x00",
                        f"/tmp/outside_{i}/file_{i}.enc",
                        128,
                        buf,
                        ppid=parent_pid,
                    )
                )

        parent_alerts = [a for a in det.alerts if a["pid"] == parent_pid]
        child_alerts = [a for a in det.alerts if a["pid"] == child_pid]
        self.assertEqual(parent_alerts, [])
        self.assertGreater(len(child_alerts), 0)


# ---------------------------------------------------------------------------
# Slow-Burn / Cumulative Profile Tests
# ---------------------------------------------------------------------------

class TestSlowBurnDetection(unittest.TestCase):
    """Verify that sporadic encryption over time is detected via cumulative profile."""

    def _det(self, **kw):
        defaults = dict(
            verify_binary_hash=False, verify_lineage=False,
            time_window=0.01,  # Tiny window so sliding-window checks never fire
            threshold_writes=100, threshold_unlinks=100,
            threshold_unique_files=100, threshold_unique_dirs=100,
        )
        defaults.update(kw)
        return RansomwareDetector(**defaults)

    def test_slow_burn_across_dirs_triggers_alert(self):
        """One high-entropy write per 'minute' across directories → cumulative alert."""
        det = self._det(cumulative_score_threshold=10)
        buf = os.urandom(128)
        # Simulate slow writes to different files in different dirs.
        # Each file = +1, each new dir = +2, so 4 files in 4 dirs = 4+8 = 12 > 10.
        targets = [
            "/home/user/Documents/report.docx",
            "/home/user/Pictures/photo.jpg",
            "/home/user/Desktop/notes.txt",
            "/home/user/Music/song.mp3",
        ]
        for f in targets:
            time.sleep(0.02)  # Ensure each write is outside the sliding window
            evt = make_event(1, 20000, "slowlocker", f, 128, buf)
            det.analyze_event(evt)

        slow_alerts = [a for a in det.alerts if a["reason"] == "Slow-burn ransomware"]
        self.assertGreater(len(slow_alerts), 0)
        self.assertEqual(slow_alerts[0]["severity"], "critical")

    def test_slow_burn_with_unlinks_triggers_faster(self):
        """High-entropy writes + source deletions accumulate score faster."""
        det = self._det(cumulative_score_threshold=12)
        buf = os.urandom(128)
        # 2 files in 2 dirs = 2+4 = 6 from writes
        # 2 unlinks of non-written files = 2*3 = 6
        # Total = 12 >= threshold
        for f in ["/home/user/a/f1.doc", "/home/user/b/f2.doc"]:
            time.sleep(0.02)
            evt = make_event(1, 20001, "slowlocker", f + ".locked", 128, buf)
            det.analyze_event(evt)
        for f in ["/home/user/a/f1.doc", "/home/user/b/f2.doc"]:
            time.sleep(0.02)
            evt = make_event(3, 20001, "slowlocker", f, 0, b"")
            det.analyze_event(evt)

        slow_alerts = [a for a in det.alerts if a["reason"] == "Slow-burn ransomware"]
        self.assertGreater(len(slow_alerts), 0)

    def test_slow_burn_in_place_overwrites_score_high(self):
        """In-place overwrites score +5 each, triggering faster."""
        det = self._det(cumulative_score_threshold=14)
        buf = os.urandom(128)
        # 2 in-place overwrites: each = +1(file) + +2(dir) + +5(overwrite) = 8
        # But second file in same dir: +1(file) + +5(overwrite) = 6
        # Total = 8 + 6 = 14 >= threshold
        files = ["/home/user/docs/a.pdf", "/home/user/docs/b.pdf"]
        for f in files:
            # Open first (so is_in_place_overwrite returns True)
            evt = make_event(0, 20002, "slowlocker", f, 0, b"")
            det.analyze_event(evt)
        for f in files:
            time.sleep(0.02)
            evt = make_event(1, 20002, "slowlocker", f, 128, buf)
            det.analyze_event(evt)

        slow_alerts = [a for a in det.alerts if a["reason"] == "Slow-burn ransomware"]
        self.assertGreater(len(slow_alerts), 0)

    def test_below_threshold_no_alert(self):
        """A few sporadic writes below the threshold → no alert."""
        det = self._det(cumulative_score_threshold=20)
        buf = os.urandom(128)
        # 2 files in 2 dirs = 2+4 = 6 < 20
        for f in ["/home/user/a/f1.doc", "/home/user/b/f2.doc"]:
            time.sleep(0.02)
            evt = make_event(1, 20003, "worker", f, 128, buf)
            det.analyze_event(evt)

        slow_alerts = [a for a in det.alerts if a["reason"] == "Slow-burn ransomware"]
        self.assertEqual(len(slow_alerts), 0)

    def test_low_entropy_writes_dont_accumulate(self):
        """Low-entropy writes (text files) don't increase the cumulative score."""
        det = self._det(cumulative_score_threshold=5)
        buf = b"A" * 128  # Low entropy
        for i in range(20):
            time.sleep(0.02)
            evt = make_event(1, 20004, "writer", f"/home/user/dir{i}/f.txt", 128, buf)
            det.analyze_event(evt)

        slow_alerts = [a for a in det.alerts if a["reason"] == "Slow-burn ransomware"]
        self.assertEqual(len(slow_alerts), 0)

    def test_unlinks_without_entropy_anchor_dont_trigger(self):
        """Delete-heavy activity alone should not be labeled ransomware."""
        det = self._det(cumulative_score_threshold=5)
        for i in range(5):
            time.sleep(0.02)
            evt = make_event(3, 20009, "cleanup", f"/home/user/docs/f{i}.doc", 0, b"")
            det.analyze_event(evt)

        slow_alerts = [a for a in det.alerts if a["reason"] == "Slow-burn ransomware"]
        self.assertEqual(len(slow_alerts), 0)

    def test_temp_like_high_entropy_files_dont_anchor_cumulative_alert(self):
        """Opaque temp artifacts should not count as ransomware-impact targets."""
        det = self._det(cumulative_score_threshold=5)
        buf = os.urandom(128)
        for i in range(4):
            time.sleep(0.02)
            evt = make_event(1, 20010, "worker", f"/tmp/blob_{i}.tmp", 128, buf)
            det.analyze_event(evt)

        slow_alerts = [a for a in det.alerts if a["reason"] == "Slow-burn ransomware"]
        self.assertEqual(len(slow_alerts), 0)

    def test_whitelisted_process_no_cumulative_alert(self):
        """Whitelisted processes don't accumulate a profile."""
        det = self._det(cumulative_score_threshold=5)
        buf = os.urandom(128)
        for i in range(20):
            time.sleep(0.02)
            evt = make_event(
                1, 20005, "gpg", f"/home/user/secret_{i}.txt.gpg", 128, buf
            )
            det.analyze_event(evt)

        slow_alerts = [a for a in det.alerts if a["reason"] == "Slow-burn ransomware"]
        self.assertEqual(len(slow_alerts), 0)

    def test_system_path_writes_dont_accumulate(self):
        """Writes to virtual system paths don't increase the cumulative score."""
        det = self._det(cumulative_score_threshold=5)
        buf = os.urandom(128)
        for i in range(20):
            time.sleep(0.02)
            evt = make_event(1, 20006, "evil", f"/proc/fake/f{i}.dat", 128, buf)
            det.analyze_event(evt)

        slow_alerts = [a for a in det.alerts if a["reason"] == "Slow-burn ransomware"]
        self.assertEqual(len(slow_alerts), 0)

    def test_alert_fires_only_once_per_pid(self):
        """The cumulative alert should fire at most once per PID."""
        det = self._det(cumulative_score_threshold=5)
        buf = os.urandom(128)
        for i in range(10):
            time.sleep(0.02)
            evt = make_event(1, 20007, "evil", f"/home/user/d{i}/f.doc", 128, buf)
            det.analyze_event(evt)

        slow_alerts = [a for a in det.alerts if a["reason"] == "Slow-burn ransomware"]
        self.assertEqual(len(slow_alerts), 1)  # Exactly one, not repeated

    def test_duplicate_file_writes_dont_double_count(self):
        """Writing to the same file twice doesn't increase the score twice."""
        det = self._det(cumulative_score_threshold=10)
        buf = os.urandom(128)
        # Same file 10 times — should only count as 1 file + 1 dir = 3 points
        for _ in range(10):
            time.sleep(0.02)
            evt = make_event(1, 20008, "evil", "/home/user/docs/f.doc", 128, buf)
            det.analyze_event(evt)

        slow_alerts = [a for a in det.alerts if a["reason"] == "Slow-burn ransomware"]
        self.assertEqual(len(slow_alerts), 0)  # 3 < 10


# ---------------------------------------------------------------------------
# Urandom Access and Kill Signal Detection Tests
# ---------------------------------------------------------------------------

class TestUrandomDetection(unittest.TestCase):
    """Verify /dev/urandom access tracking and alerting."""

    def _det(self, **kw):
        defaults = dict(
            verify_binary_hash=False, verify_lineage=False,
            time_window=10.0, threshold_writes=100,
        )
        defaults.update(kw)
        return RansomwareDetector(**defaults)

    def test_urandom_read_tracked(self):
        det = self._det()
        evt = make_event(5, 30000, "evil", "/dev/urandom", 0, b"")
        det.analyze_event(evt)
        self.assertEqual(len(det.urandom_access[30000]), 1)

    def test_urandom_feeds_cumulative_profile(self):
        det = self._det(cumulative_score_threshold=100)
        evt = make_event(5, 30001, "evil", "/dev/urandom", 0, b"")
        det.analyze_event(evt)
        profile = det._get_profile(30001)
        self.assertEqual(profile["urandom_reads"], 1)
        self.assertGreater(profile["score"], 0)

    def test_urandom_plus_writes_triggers_alert(self):
        """Urandom read + 2+ high-entropy writes to distinct files → alert."""
        det = self._det()
        buf = os.urandom(128)
        # Two high-entropy writes to distinct files
        for f in ["/home/user/a.doc", "/home/user/b.doc"]:
            evt = make_event(1, 30002, "evil", f, 128, buf)
            det.analyze_event(evt)
        # Then urandom read
        evt = make_event(5, 30002, "evil", "/dev/urandom", 0, b"")
        det.analyze_event(evt)
        urandom_alerts = [
            a for a in det.alerts if a["reason"] == "Urandom + high-entropy writes"
        ]
        self.assertGreater(len(urandom_alerts), 0)

    def test_urandom_without_writes_no_immediate_alert(self):
        """Urandom read alone should not trigger the immediate alert."""
        det = self._det()
        evt = make_event(5, 30003, "normal", "/dev/urandom", 0, b"")
        det.analyze_event(evt)
        urandom_alerts = [
            a for a in det.alerts if a["reason"] == "Urandom + high-entropy writes"
        ]
        self.assertEqual(len(urandom_alerts), 0)

    def test_whitelisted_process_urandom_no_alert(self):
        """Whitelisted processes reading urandom should not alert."""
        det = self._det()
        evt = make_event(5, 30004, "gpg", "/dev/urandom", 0, b"")
        det.analyze_event(evt)
        self.assertEqual(len(det.alerts), 0)


class TestKillSignalDetection(unittest.TestCase):
    """Verify kill signal tracking and alerting."""

    def _det(self, **kw):
        defaults = dict(
            verify_binary_hash=False, verify_lineage=False,
            time_window=10.0,
        )
        defaults.update(kw)
        return RansomwareDetector(**defaults)

    def test_kill_signal_tracked(self):
        det = self._det()
        # event type 6, size=9 (SIGKILL), filename=target comm
        evt = make_event(6, 31000, "evil", "clamd", 9, b"")
        det.analyze_event(evt)
        self.assertEqual(len(det.kill_events[31000]), 1)

    def test_kill_signal_triggers_alert(self):
        det = self._det()
        # Kill signal alert now requires at least one recent high-entropy
        # write as an entropy anchor.
        buf = os.urandom(128)
        evt = make_event(1, 31001, "evil", "/home/user/target.doc", 128, buf)
        det.analyze_event(evt)
        evt = make_event(6, 31001, "evil", "backup-agent", 15, b"")
        det.analyze_event(evt)
        kill_alerts = [a for a in det.alerts if a["reason"] == "Kill signal sent"]
        self.assertGreater(len(kill_alerts), 0)
        self.assertEqual(kill_alerts[0]["target_comm"], "backup-agent")
        self.assertEqual(kill_alerts[0]["signal"], 15)

    def test_kill_feeds_cumulative_profile(self):
        det = self._det(cumulative_score_threshold=100)
        evt = make_event(6, 31002, "evil", "mysqld", 9, b"")
        det.analyze_event(evt)
        profile = det._get_profile(31002)
        self.assertEqual(profile["kill_signals"], 1)
        self.assertGreater(profile["score"], 0)

    def test_multiple_kills_accumulate_score(self):
        det = self._det(cumulative_score_threshold=12)
        # 3 kills × 4 points = 12, but kill-only activity should not anchor a
        # ransomware cumulative alert by itself.
        for target in ["clamd", "backup-agent", "mysqld"]:
            evt = make_event(6, 31003, "evil", target, 9, b"")
            det.analyze_event(evt)
        slow_alerts = [a for a in det.alerts if a["reason"] == "Slow-burn ransomware"]
        self.assertEqual(len(slow_alerts), 0)

    def test_whitelisted_process_kill_no_alert(self):
        """Whitelisted processes sending signals should not alert."""
        det = self._det()
        evt = make_event(6, 31004, "logrotate", "old-service", 15, b"")
        det.analyze_event(evt)
        kill_alerts = [a for a in det.alerts if a["reason"] == "Kill signal sent"]
        self.assertEqual(len(kill_alerts), 0)

    def test_kill_plus_encryption_triggers_faster(self):
        """Kill signals + high-entropy writes should cross the threshold faster."""
        det = self._det(cumulative_score_threshold=10)
        buf = os.urandom(128)
        # 1 kill = 4 points
        evt = make_event(6, 31005, "evil", "clamd", 9, b"")
        det.analyze_event(evt)
        # 2 files in 2 dirs = 2×1 + 2×2 = 6 points → total 10
        for f in ["/home/user/a/f1.doc", "/home/user/b/f2.doc"]:
            time.sleep(0.02)
            evt = make_event(1, 31005, "evil", f, 128, buf)
            det.analyze_event(evt)
        slow_alerts = [a for a in det.alerts if a["reason"] == "Slow-burn ransomware"]
        self.assertGreater(len(slow_alerts), 0)


if __name__ == "__main__":
    unittest.main()
