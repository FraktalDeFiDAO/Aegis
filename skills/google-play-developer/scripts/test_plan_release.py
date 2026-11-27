import importlib.util
import json
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest
from unittest.mock import patch
import zipfile

spec = importlib.util.spec_from_file_location("plan_release", Path(__file__).with_name("plan_release.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
XML = '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app" android:versionCode="42" android:versionName="1.2"><uses-sdk android:minSdkVersion="26" android:targetSdkVersion="35"/><application android:debuggable="false"/></manifest>'


class PlanTests(unittest.TestCase):
    def artifact(self, root):
        path = root / "release.aab"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("BundleConfig.pb", b"test")
            archive.writestr("base/manifest/AndroidManifest.xml", b"protobuf-placeholder")
        return path

    def plan(self, path, xml=XML, **kwargs):
        with patch.object(module, "tool_command", return_value=["trusted-bundletool"]), patch.object(module, "invoke", side_effect=["valid", xml]) as call:
            result = module.make_plan(path, "com.example.app", "internal", "bundletool", **kwargs)
            self.assertEqual(call.call_count, 2)
            return result

    def test_actual_manifest_and_artifact_are_recorded_as_local_draft(self):
        with tempfile.TemporaryDirectory() as temp:
            path = self.artifact(Path(temp))
            result = self.plan(path)
            self.assertTrue(result["localPlanOnly"])
            self.assertEqual(result["proposedRelease"], {"status": "draft", "versionCodes": ["42"]})
            self.assertEqual(result["artifact"]["sha256"], module.digest(path))
            self.assertIn("signature-and-registered-upload-certificate", result["stillRequired"])

    def test_mismatch_debug_build_and_invalid_version_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = self.artifact(Path(temp))
            for xml in [XML.replace('package="com.example.app"', 'package="com.other.app"'), XML.replace('debuggable="false"', 'debuggable="true"'), XML.replace('versionCode="42"', 'versionCode="0"'), XML.replace('versionCode="42"', 'versionCode="42" android:versionCodeMajor="1"')]:
                with self.subTest(xml=xml), self.assertRaises(ValueError):
                    self.plan(path, xml)

    def test_rollout_fractions_are_not_percentages_or_draft_fields(self):
        with tempfile.TemporaryDirectory() as temp:
            path = self.artifact(Path(temp))
            for status, fraction in [("draft", 0.05), ("completed", 0.05), ("inProgress", 5), ("inProgress", 1), ("inProgress", float("nan")), ("inProgress", None)]:
                with self.subTest(status=status, fraction=fraction), self.assertRaises(ValueError):
                    self.plan(path, status=status, fraction=fraction)
            result = self.plan(path, status="inProgress", fraction=0.05)
            self.assertEqual(result["proposedRelease"]["userFraction"], 0.05)

    def test_duplicate_notes_and_fake_bundle_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = self.artifact(Path(temp))
            with self.assertRaises(ValueError):
                self.plan(path, notes=[{"language": "en-US", "text": "a"}, {"language": "en-US", "text": "b"}])
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("readme.txt", "not a bundle")
            with self.assertRaises(ValueError):
                self.plan(path)

    def test_tool_failure_propagates_without_creating_a_publish_action(self):
        with tempfile.TemporaryDirectory() as temp:
            path = self.artifact(Path(temp))
            with patch.object(module, "tool_command", return_value=["bundletool"]), patch.object(module, "invoke", side_effect=ValueError("validation failed")):
                with self.assertRaisesRegex(ValueError, "validation failed"):
                    module.make_plan(path, "com.example.app", "internal", "bundletool")

    def test_cli_produces_a_plan_using_a_local_tool_without_network(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            artifact = self.artifact(root)
            tool = root / "bundletool"
            tool.write_text("#!/usr/bin/env python3\nimport sys\nif sys.argv[1] == 'dump':\n print(" + repr(XML) + ")\n")
            tool.chmod(0o700)
            output = root / "plan.json"
            result = subprocess.run([sys.executable, str(Path(module.__file__)), "--aab", str(artifact), "--package", "com.example.app", "--track", "internal", "--bundletool", str(tool), "--out", str(output)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(output.read_text())["proposedRelease"]["status"], "draft")
            self.assertTrue(json.loads(result.stdout)["localPlanOnly"])


if __name__ == "__main__":
    unittest.main()
