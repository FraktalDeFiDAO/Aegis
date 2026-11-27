#!/usr/bin/env python3
"""Build a local Aegis connector release directory with SHA-256 checksums."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def host_name():
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform == "darwin":
        return "darwin"
    if sys.platform in ("win32", "cygwin"):
        return "windows"
    raise ValueError(f"Unsupported release host: {sys.platform}")


def run(command):
    subprocess.run(command, cwd=ROOT, check=True)


def write_install_notes(directory, version, os_name):
    executable = "aegis.exe" if os_name == "windows" else "aegis"
    host_executable = "aegis-native-host.exe" if os_name == "windows" else "aegis-native-host"
    registration = {
        "linux": "python3 install-native-host.py --browser chrome --extension-id STORE_ID --binary ./aegis-native-host",
        "darwin": "python3 install-native-host.py --browser chrome --extension-id STORE_ID --binary ./aegis-native-host",
        "windows": "py install-native-host.py --browser chrome --extension-id STORE_ID --binary .\\aegis-native-host.exe",
    }[os_name]
    text = f"""# Aegis Browser Connector {version} ({os_name})

1. Load the matching unpacked extension only for development, or install the reviewed store package.
2. Keep `{executable}` and `{host_executable}` in the same trusted local directory.
3. Register the store-assigned extension ID using the included installer:
   `{registration}`
4. Reload the extension after registration. The native host must be executable and registered only for that extension ID.
5. Verify every file against SHA256SUMS before installation. Never use a token from an untrusted source.

Automatic startup registers a per-user native host. Controller and extension credentials are generated per bridge start and stored owner-only. Remote policy changes and arbitrary controller JavaScript are disabled; approvals require the extension popup.

Support: https://github.com/FraktalDeFiDAO/Aegis/issues
Security model and limitations: extension/README.md and docs/CONNECTOR_COMPATIBILITY.md in the source release.
"""
    (directory / "INSTALL.md").write_text(text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "dist/release")
    parser.add_argument("--go", default="go")
    args = parser.parse_args()
    os_name = host_name()
    arch = {"amd64": "amd64", "x86_64": "amd64", "arm64": "arm64", "aarch64": "arm64"}.get(platform.machine().lower(), platform.machine().lower())
    version = json.loads((ROOT / "extension/manifest.chrome.json").read_text())["version"]
    suffix = ".exe" if os_name == "windows" else ""
    directory = args.output / f"aegis-connector-{version}-{os_name}-{arch}"
    directory.mkdir(parents=True, exist_ok=True)
    run([args.go, "build", "-o", str(directory / ("aegis" + suffix)), "./cmd/aegis"])
    run([args.go, "build", "-o", str(directory / ("aegis-native-host" + suffix)), "./cmd/aegis-native-host"])
    run(["bash", "scripts/package-extension.sh"])
    shutil.copy2(ROOT / "dist/extension/aegis-connector-chrome.zip", directory / "aegis-connector-chrome.zip")
    shutil.copy2(ROOT / "dist/extension/aegis-connector-firefox.zip", directory / "aegis-connector-firefox.zip")
    (directory / ("aegis-native-host" + suffix)).chmod(0o700)
    shutil.copy2(ROOT / "scripts/install-native-host.py", directory / "install-native-host.py")
    write_install_notes(directory, version, os_name)
    files = sorted(path for path in directory.iterdir() if path.is_file() and path.name != "SHA256SUMS")
    checksums = "".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in files)
    (directory / "SHA256SUMS").write_text(checksums)
    print(directory)


if __name__ == "__main__":
    main()
