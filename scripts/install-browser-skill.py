#!/usr/bin/env python3
"""Link a complete installed skill into local AI tools' user skill directories.

Named tools use documented skill paths. Other existing ~/.TOOL/skills stores
are included without claiming that their running application has discovered it.
Existing different files/directories are preserved and reported as conflicts.
"""
import argparse
import json
from pathlib import Path
import re
import sys

NAME = "aegis-browser"
NAMED = {
    "shared agents": ".agents/skills",
    "Codex": ".codex/skills",
    "Claude Code": ".claude/skills",
    "OpenCode": ".config/opencode/skills",
    "Kilo Code": ".kilo/skills",
    "Kilo Code legacy": ".kilocode/skills",
    "Hermes": ".hermes/skills",
    "Gemini CLI": ".gemini/skills",
    "ZCode": ".zcode/skills",
    "Antigravity": ".gemini/config/skills",
}


def install(home, source, dry_run=False, skill_name=NAME):
    source = source.expanduser().resolve()
    if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", skill_name):
        raise ValueError("Skill name must use lowercase letters/digits separated by hyphens.")
    if not (source / "SKILL.md").is_file():
        raise ValueError("Source must contain SKILL.md and its supporting resources.")
    if skill_name == NAME and not (source / "scripts/browser.py").is_file():
        raise ValueError("Aegis skill source must include its browser helper.")
    targets = {home / path: label for label, path in NAMED.items()}
    for parent in home.glob(".*"):
        # Only existing skill stores: avoid guessing new locations for other tools.
        if parent.is_dir() and (parent / "skills").is_dir():
            targets.setdefault(parent / "skills", parent.name)
    profiles = home / ".hermes/profiles"
    if profiles.is_dir():
        for path in profiles.glob("*/skills"):
            if path.is_dir():
                targets.setdefault(path, f"Hermes profile {path.parent.name}")
    report = []
    for directory, label in sorted(targets.items(), key=lambda item: str(item[0])):
        dest = directory / skill_name
        if dest.resolve() == source and dest.exists():
            status = "source" if not dest.is_symlink() else "already-linked"
        elif dest.exists() or dest.is_symlink():
            status = "conflict-preserved"
        elif dry_run:
            status = "would-link"
        else:
            directory.mkdir(parents=True, exist_ok=True)
            dest.symlink_to(source, target_is_directory=True)
            status = "linked"
        report.append({"tool": label, "path": str(dest), "status": status})
    return {"skill": skill_name, "source": str(source), "dry_run": dry_run, "targets": report}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", type=Path, default=Path.home())
    parser.add_argument("--skill", default=NAME, help="Skill folder name (default: aegis-browser)")
    parser.add_argument("--source", type=Path, help="Complete installed skill; defaults to ~/.codex/skills/<skill>")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        source = args.source or args.home / ".codex/skills" / args.skill
        result = install(args.home.expanduser().resolve(), source, args.dry_run, args.skill)
        output = json.dumps(result, indent=2) + "\n"
        if args.report:
            args.report.write_text(output)
        print(output, end="")
        return int(any(t["status"] == "conflict-preserved" for t in result["targets"]))
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
