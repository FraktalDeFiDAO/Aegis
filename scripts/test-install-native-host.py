import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("install-native-host.py")


class InstallerTests(unittest.TestCase):
    def test_install_discovers_id_and_limits_origin(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            extension = root / "extension"
            prefs = root / "config/BraveSoftware/Brave-Browser/Default/Preferences"
            prefs.parent.mkdir(parents=True)
            extension_id = "abcdefghijklmnop" * 2
            prefs.write_text(json.dumps({"extensions": {"settings": {extension_id: {"path": str(extension)}}}}))
            command = [sys.executable, str(SCRIPT), "--config-home", str(root / "config"), "--install-dir", str(root / "bin"), "--binary", "/bin/true", "--extension-dir", str(extension)]
            subprocess.run(command + ["--dry-run"], check=True, capture_output=True)
            self.assertFalse((root / "bin").exists())
            subprocess.run(command, check=True, capture_output=True)
            manifest = json.loads((prefs.parent.parent / "NativeMessagingHosts/com.aegis.bridge.json").read_text())
            self.assertEqual(manifest["allowed_origins"], [f"chrome-extension://{extension_id}/"])
            self.assertEqual(manifest["path"], str(root / "bin/aegis-native-host"))
            self.assertEqual((root / "bin/aegis-native-host").stat().st_mode & 0o777, 0o700)

    def test_rejects_invalid_or_missing_id(self):
        with tempfile.TemporaryDirectory() as directory:
            command = [sys.executable, str(SCRIPT), "--config-home", directory, "--install-dir", str(Path(directory) / "bin"), "--binary", "/bin/true"]
            for extra in ([], ["--extension-id", "*"]):
                result = subprocess.run(command + extra, capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((Path(directory) / "bin").exists())


if __name__ == "__main__":
    unittest.main()
