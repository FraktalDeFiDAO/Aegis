#!/usr/bin/env python3
"""Create a deterministic-extension ZIP using only Python's standard library."""
from pathlib import Path, PurePosixPath
import sys
import zipfile


def main():
    source = Path(sys.argv[1])
    output = Path(sys.argv[2])
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(item for item in source.rglob("*") if item.is_file()):
            name = PurePosixPath(path.relative_to(source).as_posix())
            archive.write(path, name.as_posix())
    print(f"  -> {output}")


if __name__ == "__main__":
    main()
