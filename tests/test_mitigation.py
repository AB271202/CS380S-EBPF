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
# EDR Response Chain Tests
# ---------------------------------------------------------------------------

class TestEDRResponseChain(unittest.TestCase):
    """Verify the EDR response chain."""

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
        m = Mitigator(action_mode="kill")
        with mock.patch("os.kill") as mock_kill, \
             mock.patch.object(m, "_step_quarantine", return_value=None), \
             mock.patch.object(m, "_step_network_isolate"):
            m.take_action(99999, "evil", "Test", severity="high")
            calls = [c for c in mock_kill.call_args_list if c[0][0] == 99999]
            self.assertTrue(
                any(c[0][1] == signal_mod.SIGKILL for c in calls),
                f"Expected SIGKILL for PID 99999, got {calls}",
            )

    def test_suspend_mode_sends_sigstop(self):
        m = Mitigator(action_mode="suspend")
        with mock.patch("os.kill") as mock_kill, \
             mock.patch.object(m, "_step_quarantine", return_value=None), \
             mock.patch.object(m, "_step_network_isolate"):
            m.take_action(99999, "evil", "Test", severity="high")
            calls = [c for c in mock_kill.call_args_list if c[0][0] == 99999]
            self.assertTrue(
                any(c[0][1] == signal_mod.SIGSTOP for c in calls),
                f"Expected SIGSTOP for PID 99999, got {calls}",
            )

    def test_kill_targets_children(self):
        m = Mitigator(action_mode="kill")
        with mock.patch("os.kill") as mock_kill, \
             mock.patch.object(
                 Mitigator, "_get_child_pids", return_value=[10001, 10002]
             ), \
             mock.patch.object(m, "_step_quarantine", return_value=None), \
             mock.patch.object(m, "_step_network_isolate"):
            m.take_action(99999, "evil", "Test", severity="high")
            killed_pids = {c[0][0] for c in mock_kill.call_args_list}
            self.assertIn(10001, killed_pids)
            self.assertIn(10002, killed_pids)
            self.assertIn(99999, killed_pids)

    # --- Step 2: Quarantine (move, not copy) ---

    def test_quarantine_moves_binary(self):
        m = Mitigator(action_mode="kill")
        with tempfile.TemporaryDirectory() as qdir:
            m.quarantine_dir = qdir
            # Create the binary outside the quarantine dir
            src_dir = os.path.join(qdir, "src")
            os.makedirs(src_dir)
            fake_bin = os.path.join(src_dir, "evil_bin")
            with open(fake_bin, "w") as f:
                f.write("malicious code")
            os.chmod(fake_bin, 0o755)

            result = m._step_quarantine(99999, "evil", fake_bin)
            self.assertIsNotNone(result)
            self.assertTrue(os.path.exists(result))
            # Original should be gone (moved, not copied)
            self.assertFalse(os.path.exists(fake_bin))
            # Quarantined copy should have no permissions
            mode = os.stat(result).st_mode & 0o777
            self.assertEqual(mode, 0o000)
            # Should be added to blocklist
            self.assertIn(fake_bin, m.blocklist)

    def test_quarantine_nonexistent_binary_returns_none(self):
        m = Mitigator(action_mode="kill")
        result = m._step_quarantine(99999, "evil", "/no/such/binary")
        self.assertIsNone(result)

    # --- Step 3: Network Isolation ---

    def test_network_isolation_calls_iptables(self):
        m = Mitigator(action_mode="kill", enable_network_isolation=True)
        with mock.patch.object(
            Mitigator, "_get_pid_uid", return_value=1000
        ), mock.patch("subprocess.run") as mock_run:
            m._step_network_isolate(99999, "evil")
            mock_run.assert_called_once()
            cmd = mock_run.call_args[0][0]
            self.assertIn("iptables", cmd)
            self.assertIn("1000", cmd)

    def test_network_isolation_disabled_by_default(self):
        m = Mitigator(action_mode="kill")
        with mock.patch("subprocess.run") as mock_run:
            m._step_network_isolate(99999, "evil")
            mock_run.assert_not_called()

    # --- Step 4: Remediation ---

    def test_remediation_logs_modified_files(self):
        m = Mitigator(action_mode="kill")
        files = ["/home/user/doc1.docx", "/home/user/doc2.pdf", "/home/user/doc1.docx"]
        # Should not crash; just logs
        m._step_remediate(99999, "evil", files)

    def test_write_events_populate_modified_files(self):
        det = self._det(action_mode="simulate")
        buf = os.urandom(128)
        for f in ["/home/user/a.doc", "/home/user/b.doc"]:
            evt = make_event(1, 20000, "evil", f, 128, buf)
            det.analyze_event(evt)
        self.assertGreater(len(det._pid_modified_files[20000]), 0)

    # --- Step 5: Rollback ---

    def test_rollback_triggers_snapshot(self):
        m = Mitigator(action_mode="kill", snapshot_cmd="echo snapshot_ok")
        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = mock.Mock(returncode=0, stderr="")
            m._step_rollback(99999, "evil")
            mock_run.assert_called_once()
            self.assertTrue(m._snapshot_triggered)

    def test_rollback_only_triggers_once(self):
        m = Mitigator(action_mode="kill", snapshot_cmd="echo snapshot_ok")
        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = mock.Mock(returncode=0, stderr="")
            m._step_rollback(99999, "evil")
            m._step_rollback(99999, "evil")
            mock_run.assert_called_once()

    def test_rollback_skipped_without_cmd(self):
        m = Mitigator(action_mode="kill", snapshot_cmd=None)
        with mock.patch("subprocess.run") as mock_run:
            m._step_rollback(99999, "evil")
            mock_run.assert_not_called()

    # --- Full chain integration ---

    def test_full_chain_executes_all_steps(self):
        """In kill mode, all 5 steps should execute for a critical alert."""
        m = Mitigator(
            action_mode="kill",
            snapshot_cmd="echo snap",
            enable_network_isolation=True,
        )
        with mock.patch("os.kill"), \
             mock.patch.object(m, "_step_quarantine", return_value="/quarantine/evil") as m_quar, \
             mock.patch.object(m, "_step_network_isolate") as m_net, \
             mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = mock.Mock(returncode=0, stderr="")
            m.take_action(
                99999, "evil", "Test", severity="critical",
                resolve_exe_fn=lambda pid: "/tmp/fake_evil",
            )
            m_quar.assert_called_once()
            m_net.assert_called_once()
            self.assertTrue(m._snapshot_triggered)

    def test_detector_delegates_to_mitigator(self):
        """Detector.take_action should call mitigator.take_action."""
        det = self._det(action_mode="simulate")
        det._record_alert(99999, "evil", "Test", severity="high")
        with mock.patch.object(det.mitigator, "take_action") as m_action:
            det.take_action(99999, "evil", "Test")
            m_action.assert_called_once()


if __name__ == "__main__":
    unittest.main()
