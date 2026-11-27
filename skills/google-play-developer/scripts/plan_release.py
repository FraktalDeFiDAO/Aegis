#!/usr/bin/env python3
"""Create a local release plan from an inspected AAB. Never uploads or publishes."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
import zipfile

ANDROID = "{http://schemas.android.com/apk/res/android}"


def digest(path):
    sha = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            sha.update(chunk)
    return sha.hexdigest()


def tool_command(value):
    path = Path(value).expanduser()
    if path.suffix.lower() == ".jar":
        if not path.is_file() or not shutil.which("java"):
            raise ValueError("A readable bundletool JAR and Java are required.")
        return [shutil.which("java"), "-jar", str(path.resolve())]
    executable = shutil.which(value)
    if not executable and path.is_file():
        executable = str(path.resolve())
    if not executable:
        raise ValueError("Trusted bundletool launcher not found; supply --bundletool.")
    return [executable]


def invoke(command):
    result = subprocess.run(command, capture_output=True, text=True, timeout=120)
    if result.returncode:
        # This command inspects artifacts only; avoid dumping unbounded tool logs.
        detail = (result.stderr or result.stdout).strip()[-2000:]
        raise ValueError("bundletool failed: " + detail)
    return result.stdout


def make_plan(aab, package, track, bundletool, status="draft", fraction=None, notes=None):
    if not re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+", package, flags=re.ASCII):
        raise ValueError("Expected an explicit Android package/application ID.")
    if not track or track.strip() != track or any(c in track for c in "\r\n"):
        raise ValueError("An exact track identifier is required.")
    if status not in ("draft", "completed", "inProgress"):
        raise ValueError("Plan status must be draft, completed, or inProgress.")
    if status == "inProgress":
        if fraction is None or not math.isfinite(fraction) or not 0 < fraction < 1:
            raise ValueError("inProgress requires a fraction strictly between 0 and 1 (5% is 0.05).")
    elif fraction is not None:
        raise ValueError("A user fraction is valid only for an inProgress plan.")
    notes = notes if notes is not None else []
    if not isinstance(notes, list) or any(not isinstance(n, dict) or set(n) != {"language", "text"} or not isinstance(n["language"], str) or not n["language"].strip() or not isinstance(n["text"], str) for n in notes):
        raise ValueError("Notes must be a list of language/text string objects.")
    if len({n["language"] for n in notes}) != len(notes):
        raise ValueError("Release-note languages must be unique.")
    aab = Path(aab).expanduser().resolve()
    if aab.suffix.lower() != ".aab" or not aab.is_file():
        raise ValueError("An existing .aab artifact is required.")
    before = digest(aab)
    with zipfile.ZipFile(aab) as archive:
        if not {"BundleConfig.pb", "base/manifest/AndroidManifest.xml"}.issubset(archive.namelist()):
            raise ValueError("Artifact lacks required Android App Bundle entries.")
    tool = tool_command(bundletool)
    invoke(tool + ["validate", "--bundle=" + str(aab)])
    manifest = ET.fromstring(invoke(tool + ["dump", "manifest", "--bundle=" + str(aab), "--module=base"]))
    if manifest.tag != "manifest" or manifest.get("package") != package:
        raise ValueError("Artifact manifest package does not match the requested app.")
    version_text = manifest.get(ANDROID + "versionCode", "")
    if not version_text.isdecimal() or not 1 <= int(version_text) <= 2100000000:
        raise ValueError("Manifest must contain a valid Play versionCode.")
    if manifest.get(ANDROID + "versionCodeMajor", "0") not in ("", "0"):
        raise ValueError("Nonzero versionCodeMajor requires manual Play version-code verification.")
    application = manifest.find("application")
    if application is None:
        raise ValueError("Manifest lacks an application element.")
    debug = application.get(ANDROID + "debuggable", "false").lower()
    if debug not in ("false", "0"):
        raise ValueError("Release artifact is debuggable or its debuggable value is unresolved.")
    if digest(aab) != before:
        raise ValueError("Artifact changed during inspection; rebuild the plan from a stable file.")
    sdk = manifest.find("uses-sdk")
    release = {"status": status, "versionCodes": [str(int(version_text))]}
    if notes:
        release["releaseNotes"] = notes
    if fraction is not None:
        release["userFraction"] = fraction
    return {
        "schemaVersion": 1, "localPlanOnly": True,
        "packageName": package, "track": track,
        "artifact": {"path": str(aab), "sha256": before, "sizeBytes": aab.stat().st_size},
        "manifest": {"versionCode": int(version_text), "versionName": manifest.get(ANDROID + "versionName"),
                     "minSdkVersion": sdk.get(ANDROID + "minSdkVersion") if sdk is not None else None,
                     "targetSdkVersion": sdk.get(ANDROID + "targetSdkVersion") if sdk is not None else None},
        "proposedRelease": release,
        "verified": ["bundletool-validation", "manifest-package", "version-code-format", "non-debuggable", "artifact-sha256"],
        "stillRequired": ["signature-and-registered-upload-certificate", "remote-version-and-track-conflicts", "tests-on-this-build", "current-policy-and-account-eligibility", "review-and-publish-authorization"],
        "warning": "Candidate release only. Reconcile current track state before applying; no upload or publication was performed.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--aab", required=True, type=Path)
    parser.add_argument("--package", required=True)
    parser.add_argument("--track", required=True)
    parser.add_argument("--bundletool", required=True, help="Trusted JAR or launcher")
    parser.add_argument("--status", choices=("draft", "completed", "inProgress"), default="draft")
    parser.add_argument("--fraction", type=float)
    parser.add_argument("--notes-file", type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.out.resolve() == args.aab.resolve():
            raise ValueError("Plan output must not overwrite the AAB.")
        notes = json.loads(args.notes_file.read_text()) if args.notes_file else None
        plan = make_plan(args.aab, args.package, args.track, args.bundletool, args.status, args.fraction, notes)
        args.out.write_text(json.dumps(plan, indent=2) + "\n")
        print(json.dumps({"localPlanOnly": True, "output": str(args.out.resolve()), "packageName": plan["packageName"], "versionCode": plan["manifest"]["versionCode"], "track": plan["track"], "status": plan["proposedRelease"]["status"]}))
        return 0
    except (OSError, ValueError, zipfile.BadZipFile, ET.ParseError, subprocess.TimeoutExpired) as exc:
        # Timeout text can include paths, but this helper never accepts credentials.
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
