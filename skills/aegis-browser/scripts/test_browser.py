import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HELPER = Path(__file__).with_name("browser.py")


class BrowserHelperTests(unittest.TestCase):
    def invoke(self, root, result, params=None, extra=None):
        fake = root / "aegis"
        fake.write_text("#!/usr/bin/env python3\nimport json,sys\nfrom pathlib import Path\n"
                        "args=sys.argv\n"
                        "params=json.loads(Path(args[args.index('--params-file')+1]).read_text())\n"
                        "assert '--params' not in args\n"
                        "Path(__file__).with_name('received.json').write_text(json.dumps(params))\n"
                        f"result=json.loads({json.dumps(json.dumps(result))})\n"
                        "Path(args[args.index('--output')+1]).write_text(json.dumps(result))\n")
        fake.chmod(0o700)
        command = [sys.executable, str(HELPER), "fill", "--aegis", str(fake), "--params", json.dumps(params or {})]
        return subprocess.run(command + (extra or []), text=True, capture_output=True)

    def test_exit_zero_with_rejected_result_is_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.invoke(Path(directory), {"success": False, "err": {"code": "permission_denied", "message": "blocked"}})
            self.assertEqual(result.returncode, 1)
            self.assertEqual(json.loads(result.stderr)["err"]["code"], "permission_denied")

    def test_values_are_passed_literally_without_shell_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            params = {"tabId": 123, "value": f"$(touch {root / 'unexpected'}) `echo secret`\nquote'\""}
            result = self.invoke(root, {"success": True, "data": {"filled": True}}, params)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads((root / "received.json").read_text()), params)
            self.assertFalse((root / "unexpected").exists())

    def test_missing_success_is_unverified(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.invoke(Path(directory), {"data": {"ok": True}})
            self.assertEqual(result.returncode, 1)

    def test_saved_artifact_is_not_dumped_to_stdout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            envelope = {"success": True, "data": {"screenshot": "private-pixels"}}
            result = self.invoke(root, envelope, extra=["--output", str(root / "capture.json")])
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("private-pixels", result.stdout)
            self.assertEqual(json.loads((root / "capture.json").read_text()), envelope)

    def test_remote_bridge_is_rejected_before_command_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = self.invoke(root, {"success": True}, extra=["--bridge-url", "ws://192.0.2.1:9876/ws"])
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / "received.json").exists())


if __name__ == "__main__":
    unittest.main()
