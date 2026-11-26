#!/usr/bin/env python3
"""Register the Aegis native host for a per-user Linux Chromium browser."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import sys

NAME = "com.aegis.bridge"
BROWSERS = {"brave": "BraveSoftware/Brave-Browser", "chrome": "google-chrome", "chromium": "chromium"}
ROOT = Path(__file__).resolve().parents[1]


def installed_id(browser_dir, extension_dir):
    matches = set()
    for pattern in ("*/Preferences", "*/Secure Preferences"):
        for prefs in browser_dir.glob(pattern):
            try:
                settings = json.loads(prefs.read_text()).get("extensions", {}).get("settings", {})
                for extension_id, info in settings.items():
                    path = info.get("path", "")
                    if path and Path(path).is_absolute() and Path(path).resolve() == extension_dir.resolve():
                        matches.add(extension_id)
            except (OSError, ValueError, TypeError):
                continue
    if len(matches) != 1:
        raise ValueError("Cannot determine the installed Aegis extension ID. Pass --extension-id with its ID from the browser extension manager.")
    return matches.pop()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser", choices=BROWSERS, default="brave")
    parser.add_argument("--extension-id")
    parser.add_argument("--extension-dir", type=Path, default=ROOT / "dist/extension/chrome")
    parser.add_argument("--binary", type=Path, default=ROOT / "dist/aegis-native-host")
    parser.add_argument("--config-home", type=Path, default=Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")))
    parser.add_argument("--install-dir", type=Path, default=Path.home() / ".local/lib/aegis")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if not sys.platform.startswith("linux"):
        parser.error("This installer currently supports Linux browsers only.")
    browser_dir = args.config_home / BROWSERS[args.browser]
    try:
        extension_id = args.extension_id or installed_id(browser_dir, args.extension_dir)
        if not re.fullmatch("[a-p]{32}", extension_id):
            raise ValueError("Expected a Chromium extension ID (32 letters a through p).")
        if not args.binary.is_file() or not os.access(args.binary, os.X_OK):
            raise ValueError("Build the native host first: go build -o dist/aegis-native-host ./cmd/aegis-native-host")
        executable = args.install_dir.resolve() / "aegis-native-host"
        manifest_path = browser_dir / "NativeMessagingHosts" / (NAME + ".json")
        manifest = {"name": NAME, "description": "Starts the local Aegis browser bridge", "path": str(executable), "type": "stdio", "allowed_origins": [f"chrome-extension://{extension_id}/"]}
        print(f"Extension ID: {extension_id}\nNative host: {executable}\nRegistration: {manifest_path}")
        if args.dry_run:
            return
        executable.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Replace atomically so reinstalling does not truncate a running host.
        temp_binary = executable.with_suffix(".tmp")
        shutil.copyfile(args.binary, temp_binary)
        temp_binary.chmod(0o700)
        temp_binary.replace(executable)
        manifest_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        temp_manifest = manifest_path.with_suffix(".tmp")
        temp_manifest.write_text(json.dumps(manifest, indent=2) + "\n")
        temp_manifest.chmod(0o600)
        temp_manifest.replace(manifest_path)
        print("Installed. Reload Aegis in the browser extension manager to enable nativeMessaging and automatic startup.")
    except (OSError, ValueError) as exc:
        parser.exit(1, f"{exc}\n")


if __name__ == "__main__":
    main()
