#!/usr/bin/env python3
"""Send one Aegis browser command and require a successful response envelope."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit


def executable(explicit):
    if explicit:
        candidates = [explicit]
    elif os.environ.get("AEGIS_BIN"):
        candidates = [os.environ["AEGIS_BIN"]]
    else:
        candidates = [str(Path.cwd() / "aegis"), shutil.which("aegis"),
                      str(Path(__file__).resolve().parents[3] / "aegis"),
                      "/home/admministrator/projects/FraktalDeFiDAO/Aegis/aegis"]
    for candidate in candidates:
        if not candidate:
            continue
        path = Path(shutil.which(candidate) or candidate).expanduser().resolve()
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
    raise ValueError("Aegis executable not found; set AEGIS_BIN or pass --aegis.")


def local_bridge(value):
    parsed = urlsplit(value)
    host = parsed.hostname
    try:
        loopback = host == "localhost" or ipaddress.ip_address(host).is_loopback
        port = parsed.port
    except (ValueError, TypeError):
        loopback, port = False, None
    if parsed.scheme != "ws" or not loopback or not port or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("Bridge URL must be a loopback ws:// URL with an explicit port.")
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--params", default=None, help="JSON object")
    group.add_argument("--params-file", type=Path)
    parser.add_argument("--aegis", help="Aegis executable; overrides AEGIS_BIN")
    parser.add_argument("--bridge-url", type=local_bridge)
    parser.add_argument("--output", type=Path, help="Save full envelope instead of printing its data")
    parser.add_argument("--timeout", type=float, default=45, help="Process timeout in seconds; no automatic retries")
    args = parser.parse_args()
    try:
        if args.timeout <= 0:
            raise ValueError("Timeout must be positive.")
        params = json.loads(args.params_file.read_text() if args.params_file else args.params or "{}")
        if not isinstance(params, dict):
            raise ValueError("Parameters must be a JSON object.")
        binary = executable(args.aegis)
        with tempfile.TemporaryDirectory(prefix="aegis-browser-") as temp:
            result_path = Path(temp) / "result.json"
            params_path = Path(temp) / "params.json"
            params_path.write_text(json.dumps(params))
            params_path.chmod(0o600)
            argv = [binary, "connect", "--connector"]
            if args.bridge_url:
                argv += ["--bridge-url", args.bridge_url]
            argv += ["send", "--command", args.command, "--params-file", str(params_path), "--timeout", f"{args.timeout}s", "--output", str(result_path)]
            try:
                process = subprocess.run(argv, capture_output=True, text=True, timeout=args.timeout)
            except subprocess.TimeoutExpired:
                raise ValueError("Command timed out; outcome may be uncertain. Inspect browser state before retrying.") from None
            if not result_path.is_file():
                raise ValueError(f"No response envelope (CLI exit {process.returncode}). Check connection/permissions with connect status; outcome may be uncertain.")
            try:
                result = json.loads(result_path.read_text())
            except (ValueError, UnicodeError):
                raise ValueError("Invalid response JSON; outcome is unverified.") from None
        if not isinstance(result, dict):
            raise ValueError("Expected a response object; outcome is unverified.")
        success = result.get("success") is True and process.returncode == 0
        if args.output:
            args.output.write_text(json.dumps(result, indent=2) + "\n")
        if not success:
            error = result.get("err") or {"code": "command_failed", "message": result.get("error") or f"Unverified result (CLI exit {process.returncode})."}
            print(json.dumps({"success": False, "err": error}), file=sys.stderr)
            return 1
        if args.output:
            print(json.dumps({"success": True, "output": str(args.output.resolve())}))
        else:
            print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError) as exc:
        print(json.dumps({"success": False, "err": {"code": "execution_error", "message": str(exc)}}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
