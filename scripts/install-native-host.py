#!/usr/bin/env python3
"""Register the Aegis native host for a per-user Chromium browser."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import sys

NAME = "com.aegis.bridge"
BROWSERS = {
    "linux": {"brave": "BraveSoftware/Brave-Browser", "chrome": "google-chrome", "chromium": "chromium"},
    "darwin": {"brave": "BraveSoftware/Brave-Browser", "chrome": "Google/Chrome", "chromium": "Chromium"},
    "windows": {"brave": "BraveSoftware/Brave-Browser/User Data", "chrome": "Google/Chrome/User Data", "chromium": "Chromium/User Data"},
}
ROOT = Path(__file__).resolve().parents[1]


def host_platform():
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform == "darwin":
        return "darwin"
    if sys.platform in ("win32", "cygwin"):
        return "windows"
    raise ValueError(f"Unsupported platform: {sys.platform}")


def defaults(platform):
    home = Path.home()
    if platform == "darwin":
        return home / "Library/Application Support", home / "Library/Application Support/Aegis"
    if platform == "windows":
        config = Path(os.environ.get("LOCALAPPDATA", home / "AppData/Local"))
        return config, config / "Aegis"
    return Path(os.environ.get("XDG_CONFIG_HOME", home / ".config")), home / ".local/lib/aegis"


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


def windows_registration(browser):
    return {
        "brave": "Software\\BraveSoftware\\Brave-Browser\\NativeMessagingHosts\\" + NAME,
        "chrome": "Software\\Google\\Chrome\\NativeMessagingHosts\\" + NAME,
        "chromium": "Software\\Chromium\\NativeMessagingHosts\\" + NAME,
    }[browser]


def register_windows(registry_path, manifest_path):
    import winreg
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, registry_path) as key:
        winreg.SetValueEx(key, "", 0, winreg.REG_SZ, str(manifest_path))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser", choices=BROWSERS["linux"], default="brave")
    parser.add_argument("--platform", choices=BROWSERS, default=host_platform(), help=argparse.SUPPRESS)
    parser.add_argument("--extension-id")
    parser.add_argument("--extension-dir", type=Path, default=ROOT / "dist/extension/chrome")
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--config-home", type=Path)
    parser.add_argument("--install-dir", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    default_config, default_install = defaults(args.platform)
    config_home = args.config_home or default_config
    install_dir = args.install_dir or default_install
    binary = args.binary or ROOT / "dist" / ("aegis-native-host.exe" if args.platform == "windows" else "aegis-native-host")
    browser_dir = config_home / BROWSERS[args.platform][args.browser]
    try:
        extension_id = args.extension_id or installed_id(browser_dir, args.extension_dir)
        if not re.fullmatch("[a-p]{32}", extension_id):
            raise ValueError("Expected a Chromium extension ID (32 letters a through p).")
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise ValueError("Build the native host first: go build -o dist/aegis-native-host ./cmd/aegis-native-host")
        executable = install_dir.resolve() / ("aegis-native-host.exe" if args.platform == "windows" else "aegis-native-host")
        if args.platform == "windows":
            manifest_path = install_dir.resolve() / "NativeMessagingHosts" / (NAME + ".json")
            registration = windows_registration(args.browser)
        else:
            manifest_path = browser_dir / "NativeMessagingHosts" / (NAME + ".json")
            registration = manifest_path
        manifest = {"name": NAME, "description": "Starts the local Aegis browser bridge", "path": str(executable), "type": "stdio", "allowed_origins": [f"chrome-extension://{extension_id}/"]}
        print(f"Extension ID: {extension_id}\nNative host: {executable}\nManifest: {manifest_path}\nRegistration: {registration}")
        if args.dry_run:
            return
        executable.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        temp_binary = executable.with_suffix(".tmp")
        shutil.copyfile(binary, temp_binary)
        temp_binary.chmod(0o700)
        temp_binary.replace(executable)
        manifest_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        temp_manifest = manifest_path.with_suffix(".tmp")
        temp_manifest.write_text(json.dumps(manifest, indent=2) + "\n")
        temp_manifest.chmod(0o600)
        temp_manifest.replace(manifest_path)
        if args.platform == "windows":
            register_windows(registration, manifest_path)
        print("Installed. Reload Aegis in the browser extension manager to enable nativeMessaging and automatic startup.")
    except (OSError, ValueError) as exc:
        parser.exit(1, f"{exc}\n")


if __name__ == "__main__":
    main()
