"""EDR Response Chain — 6-step mitigation for detected ransomware.

Steps mirror production AV/EDR tools (CrowdStrike, SentinelOne):
  1. Process Kill   — terminate the process tree
  2. Quarantine     — copy binary to secure location, strip permissions
  3. Network Isolate — block outbound traffic via iptables
  4. Remediate      — log modified files for recovery
  5. Rollback       — trigger a filesystem snapshot (Btrfs/ZFS)
  6. Harden Binary  — strip exec bit, add to persistent blocklist
"""

import os
import shutil
import signal as signal_mod
import stat
import subprocess
import time


class Mitigator:
    """Executes the graduated EDR response chain.

    Parameters
    ----------
    action_mode : str
        ``"simulate"`` (log only), ``"suspend"`` (SIGSTOP), or
        ``"kill"`` (full chain with SIGKILL).
    snapshot_cmd : str or None
        Shell command for filesystem snapshot on critical alerts.
    quarantine_dir : str
        Directory to store quarantined binaries.
    enable_network_isolation : bool
        Whether to install iptables rules to block the offending UID.
    """

    def __init__(
        self,
        action_mode="simulate",
        snapshot_cmd=None,
        quarantine_dir=None,
        enable_network_isolation=False,
    ):
        self.action_mode = action_mode
        self.snapshot_cmd = snapshot_cmd
        self._snapshot_triggered = False
        self.quarantine_dir = quarantine_dir or "/var/lib/ransomware-monitor/quarantine"
        self.enable_network_isolation = enable_network_isolation
        self.blocklist: set[str] = set()

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def take_action(self, pid, comm, reason, severity="unknown",
                    resolve_exe_fn=None, modified_files=None):
        """Run the full response chain for a flagged process.

        Parameters
        ----------
        pid, comm, reason : int, str, str
            Identity and reason for the alert.
        severity : str
            Alert severity (``"critical"`` triggers rollback).
        resolve_exe_fn : callable or None
            ``fn(pid) -> str|None`` that resolves the on-disk binary path.
        modified_files : list[str] or None
            Files the process has modified (for remediation logging).
        """
        print(
            f"[X] ACTION ({self.action_mode}): {comm} (PID {pid}) — "
            f"{reason} [severity={severity}]"
        )

        if self.action_mode == "simulate":
            print(f"      [simulate] Would execute full EDR chain for PID {pid}")
            return

        # Step 1: Process Kill / Suspend
        self._step_kill_process(pid, comm)

        # Step 2: Quarantine the binary
        exe_path = resolve_exe_fn(pid) if resolve_exe_fn else None
        quarantined_path = self._step_quarantine(pid, comm, exe_path)

        # Step 3: Network Isolation
        self._step_network_isolate(pid, comm)

        # Step 4: Remediation
        self._step_remediate(pid, comm, modified_files)

        # Step 5: Rollback (critical only)
        if severity == "critical":
            self._step_rollback(pid, comm)

        # Step 6: Binary Hardening
        self._step_harden_binary(pid, comm, exe_path, quarantined_path)

    # ------------------------------------------------------------------
    # Step 1: Process Kill
    # ------------------------------------------------------------------

    def _step_kill_process(self, pid, comm):
        sig = signal_mod.SIGSTOP if self.action_mode == "suspend" else signal_mod.SIGKILL
        sig_name = "SIGSTOP" if self.action_mode == "suspend" else "SIGKILL"

        for cpid in self._get_child_pids(pid):
            try:
                os.kill(cpid, sig)
                print(f"      [step1] Sent {sig_name} to child PID {cpid}")
            except (ProcessLookupError, PermissionError):
                pass

        try:
            os.kill(pid, sig)
            print(f"      [step1] Sent {sig_name} to PID {pid} ({comm})")
        except ProcessLookupError:
            print(f"      [step1] PID {pid} already exited")
        except PermissionError:
            print(f"      [step1] Permission denied for PID {pid}")
        except Exception as exc:
            print(f"      [step1] Error signaling PID {pid}: {exc}")

    @staticmethod
    def _get_child_pids(pid):
        try:
            with open(f"/proc/{pid}/task/{pid}/children", "r") as fh:
                return [int(p) for p in fh.read().split() if p.strip()]
        except (OSError, ValueError):
            return []

    # ------------------------------------------------------------------
    # Step 2: Quarantine
    # ------------------------------------------------------------------

    def _step_quarantine(self, pid, comm, exe_path):
        if not exe_path or not os.path.isfile(exe_path):
            print(f"      [step2] Cannot quarantine: binary not found for PID {pid}")
            return None
        try:
            os.makedirs(self.quarantine_dir, exist_ok=True)
            dest = os.path.join(
                self.quarantine_dir,
                f"{comm}_{pid}_{int(time.time())}_{os.path.basename(exe_path)}",
            )
            shutil.copy2(exe_path, dest)
            os.chmod(dest, 0o000)
            print(f"      [step2] Quarantined {exe_path} → {dest}")
            return dest
        except (OSError, shutil.Error) as exc:
            print(f"      [step2] Quarantine failed for {exe_path}: {exc}")
            return None

    # ------------------------------------------------------------------
    # Step 3: Network Isolation
    # ------------------------------------------------------------------

    def _step_network_isolate(self, pid, comm):
        if not self.enable_network_isolation:
            print(f"      [step3] Network isolation disabled (use --enable-network-isolation)")
            return
        uid = self._get_pid_uid(pid)
        if uid is None:
            print(f"      [step3] Cannot determine UID for PID {pid}")
            return
        try:
            subprocess.run(
                ["iptables", "-A", "OUTPUT",
                 "-m", "owner", "--uid-owner", str(uid),
                 "-j", "DROP"],
                capture_output=True, text=True, timeout=5,
            )
            print(f"      [step3] Blocked outbound traffic for UID {uid} (PID {pid})")
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            print(f"      [step3] Network isolation failed: {exc}")

    @staticmethod
    def _get_pid_uid(pid):
        try:
            with open(f"/proc/{pid}/status", "r") as fh:
                for line in fh:
                    if line.startswith("Uid:"):
                        return int(line.split()[1])
        except (OSError, ValueError, IndexError):
            pass
        return None

    # ------------------------------------------------------------------
    # Step 4: Remediation
    # ------------------------------------------------------------------

    @staticmethod
    def _step_remediate(pid, comm, modified_files=None):
        if not modified_files:
            print(f"      [step4] No tracked file modifications for PID {pid}")
            return
        unique = list(dict.fromkeys(modified_files))
        print(f"      [step4] {len(unique)} files modified by {comm} (PID {pid}):")
        for f in unique[:20]:
            print(f"              - {f}")
        if len(unique) > 20:
            print(f"              ... and {len(unique) - 20} more")

    # ------------------------------------------------------------------
    # Step 5: Rollback
    # ------------------------------------------------------------------

    def _step_rollback(self, pid, comm):
        if not self.snapshot_cmd:
            print(f"      [step5] No snapshot command configured (use --snapshot-cmd)")
            return
        if self._snapshot_triggered:
            print(f"      [step5] Snapshot already triggered this session")
            return
        self._snapshot_triggered = True
        print(f"      [step5] Running snapshot: {self.snapshot_cmd}")
        try:
            result = subprocess.run(
                self.snapshot_cmd, shell=True, timeout=30,
                capture_output=True, text=True,
            )
            if result.returncode == 0:
                print(f"      [step5] Snapshot created successfully")
            else:
                print(f"      [step5] Snapshot command exited with code {result.returncode}")
                if result.stderr:
                    print(f"              stderr: {result.stderr.strip()}")
        except subprocess.TimeoutExpired:
            print(f"      [step5] Snapshot command timed out")
        except Exception as exc:
            print(f"      [step5] Snapshot failed: {exc}")

    # ------------------------------------------------------------------
    # Step 6: Binary Hardening
    # ------------------------------------------------------------------

    def _step_harden_binary(self, pid, comm, exe_path, quarantined_path):
        if exe_path and os.path.isfile(exe_path):
            try:
                current = os.stat(exe_path).st_mode
                os.chmod(exe_path, current & ~(stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
                print(f"      [step6] Stripped exec bit from {exe_path}")
            except OSError as exc:
                print(f"      [step6] Cannot strip exec bit from {exe_path}: {exc}")
        if exe_path:
            self.blocklist.add(exe_path)
            print(f"      [step6] Added {exe_path} to blocklist ({len(self.blocklist)} entries)")
