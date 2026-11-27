import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("installer", Path(__file__).with_name("install-browser-skill.py"))
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class InstallTests(unittest.TestCase):
    def source(self, home):
        source = home / ".codex/skills/aegis-browser"
        (source / "scripts").mkdir(parents=True)
        (source / "SKILL.md").write_text("skill")
        (source / "scripts/browser.py").write_text("helper")
        return source

    def test_named_existing_and_repeated_installation(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            source = self.source(home)
            (home / ".other/skills").mkdir(parents=True)
            first = installer.install(home, source)
            for target in first["targets"]:
                self.assertEqual(Path(target["path"]).resolve(), source)
                self.assertTrue((Path(target["path"]) / "scripts/browser.py").is_file())
            second = installer.install(home, source)
            self.assertTrue(all(t["status"] in ("already-linked", "source") for t in second["targets"]))
            self.assertFalse((home / ".unknown/skills").exists())

    def test_conflicts_and_dry_run_preserve_files(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            source = self.source(home)
            conflict = home / ".claude/skills/aegis-browser"
            conflict.mkdir(parents=True)
            (conflict / "SKILL.md").write_text("user-owned")
            result = installer.install(home, source, dry_run=True)
            self.assertTrue(any(t["status"] == "conflict-preserved" for t in result["targets"]))
            self.assertEqual((conflict / "SKILL.md").read_text(), "user-owned")
            self.assertFalse((home / ".hermes").exists())

    def test_another_skill_uses_its_own_name_and_resources(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            source = home / ".codex/skills/google-play-developer"
            source.mkdir(parents=True)
            (source / "SKILL.md").write_text("play skill")
            result = installer.install(home, source, skill_name="google-play-developer")
            self.assertEqual(result["skill"], "google-play-developer")
            self.assertTrue(all(Path(t["path"]).name == "google-play-developer" for t in result["targets"]))
            self.assertFalse((home / ".claude/skills/aegis-browser").exists())
            with self.assertRaises(ValueError):
                installer.install(home, source, skill_name="../escape")


if __name__ == "__main__":
    unittest.main()
