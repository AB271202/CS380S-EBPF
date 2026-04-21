#!/usr/bin/env python3
import importlib.util
import os
from pathlib import Path
import sys
import types
import unittest
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
MAIN_PATH = REPO_ROOT / "agent" / "main.py"
BPF_PATH = REPO_ROOT / "bpf" / "monitor.bpf.c"


def load_main_module():
    """Load agent/main.py with lightweight fake dependencies."""
    fake_bcc = types.ModuleType("bcc")
    fake_bcc.BPF = object

    fake_detector = types.ModuleType("detector")
    fake_detector.RansomwareDetector = object

    module_name = "agent_main_under_test"
    spec = importlib.util.spec_from_file_location(module_name, MAIN_PATH)
    module = importlib.util.module_from_spec(spec)
    old_bcc = sys.modules.get("bcc")
    old_detector = sys.modules.get("detector")
    try:
        sys.modules["bcc"] = fake_bcc
        sys.modules["detector"] = fake_detector
        spec.loader.exec_module(module)
    finally:
        if old_bcc is not None:
            sys.modules["bcc"] = old_bcc
        else:
            sys.modules.pop("bcc", None)
        if old_detector is not None:
            sys.modules["detector"] = old_detector
        else:
            sys.modules.pop("detector", None)
    return module


class FakeEventTable:
    def open_perf_buffer(self, callback, page_cnt=None, lost_cb=None):
        self.callback = callback
        self.page_cnt = page_cnt
        self.lost_cb = lost_cb


class FakeBPF:
    def __init__(self, src_file=None):
        self.src_file = src_file
        self.events = FakeEventTable()

    def __getitem__(self, key):
        if key != "events":
            raise KeyError(key)
        return self.events

    def perf_buffer_poll(self):
        raise KeyboardInterrupt


class FakeDetector:
    last_kwargs = None

    def __init__(self, **kwargs):
        type(self).last_kwargs = kwargs

    def analyze_event(self, event):
        return None


class TestMainWiring(unittest.TestCase):
    def test_env_and_cli_detector_wiring(self):
        module = load_main_module()

        with mock.patch.object(module, "BPF", FakeBPF), \
             mock.patch.object(module, "RansomwareDetector", FakeDetector), \
             mock.patch.object(module.os, "geteuid", return_value=0), \
             mock.patch.object(module.os.path, "exists", return_value=True), \
             mock.patch.object(
                 sys,
                 "argv",
                 [
                     "main.py",
                     "--whitelist-config", "/tmp/whitelist.json",
                     "--canary-dir", "/tmp/canary-a",
                     "--disable-lineage-verification",
                 ],
             ), \
             mock.patch.dict(
                 os.environ,
                 {
                     "CANARY_DIRS": "/tmp/canary-a,/tmp/canary-b,/tmp/canary-c",
                     "DISABLE_BINARY_HASH_VERIFICATION": "1",
                 },
                 clear=False,
             ):
            module.main()

        self.assertIsNotNone(FakeDetector.last_kwargs)
        self.assertEqual(
            FakeDetector.last_kwargs["whitelist_config"],
            "/tmp/whitelist.json",
        )
        self.assertEqual(
            FakeDetector.last_kwargs["canary_dirs"],
            ["/tmp/canary-a", "/tmp/canary-b", "/tmp/canary-c"],
        )
        self.assertFalse(FakeDetector.last_kwargs["verify_binary_hash"])
        self.assertFalse(FakeDetector.last_kwargs["verify_lineage"])

    def test_split_path_list_helper(self):
        module = load_main_module()
        self.assertEqual(
            module._split_path_list("/tmp/a,/tmp/b:/tmp/c;/tmp/d"),
            ["/tmp/a", "/tmp/b", "/tmp/c", "/tmp/d"],
        )


class TestBpfOpenVisibility(unittest.TestCase):
    def test_open_hook_not_limited_to_ocreat(self):
        source = BPF_PATH.read_text(encoding="utf-8")
        self.assertNotIn("if (!(flags & O_CREAT))", source)


if __name__ == "__main__":
    unittest.main()
