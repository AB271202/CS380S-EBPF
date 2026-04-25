"""Shared test helpers and imports for the ransomware-monitor test suite."""

import os
import sys
import types

# Allow importing from the agent and tests directories.
_here = os.path.dirname(os.path.abspath(__file__))
_agent = os.path.join(_here, "..", "agent")
if _agent not in sys.path:
    sys.path.insert(0, _agent)
if _here not in sys.path:
    sys.path.insert(0, _here)

from detector import (  # noqa: F401 — re-exported for test files
    DEFAULT_WHITELISTED_PROCESSES,
    MAGIC_BYTES,
    RansomwareDetector,
)
from mitigator import Mitigator  # noqa: F401


def make_event(event_type, pid, comm, filename, size=0, buffer=b"", ppid=0):
    """Build a lightweight event object that quacks like a BPF event."""
    evt = types.SimpleNamespace()
    evt.type = event_type
    evt.pid = pid
    evt.ppid = ppid
    evt.comm = comm.encode("utf-8") if isinstance(comm, str) else comm
    evt.filename = filename.encode("utf-8") if isinstance(filename, str) else filename
    evt.size = size
    evt.buffer = buffer
    return evt
