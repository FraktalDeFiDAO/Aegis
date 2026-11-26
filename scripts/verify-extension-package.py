#!/usr/bin/env python3
"""Validate the Chrome candidate ZIP without extracting it or claiming store approval."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import sys
import zipfile


def verify(path):
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise ValueError('Duplicate ZIP entries')
        for name in names:
            part = PurePosixPath(name)
            if part.is_absolute() or '..' in part.parts or '\\' in name:
                raise ValueError('Unsafe ZIP path')
            if any(p.startswith('.') or p in ('node_modules', '__pycache__') for p in part.parts):
                raise ValueError('Development/cache files in ZIP')
        manifest = json.loads(archive.read('manifest.json'))
        if manifest.get('manifest_version') != 3:
            raise ValueError('Expected Chrome Manifest V3')
        if 'key' in manifest or 'update_url' in manifest:
            raise ValueError('Development key or external update URL in store package')
        if 'nativeMessaging' not in manifest.get('permissions', []):
            raise ValueError('Companion startup permission missing')
        references = [manifest['background']['service_worker'], 'browser-control.js']
        for content in manifest.get('content_scripts', []):
            references.extend(content.get('js', []))
        references.extend(manifest.get('icons', {}).values())
        action = manifest.get('action', {})
        references.append(action['default_popup'])
        references.extend(action.get('default_icon', {}).values())
        references.append('popup.js')
        for name in references:
            if name not in names or not archive.read(name):
                raise ValueError('Missing or empty manifest asset: ' + name)
        bad = archive.testzip()
        if bad:
            raise ValueError('ZIP CRC failure: ' + bad)
    return {'file': str(path), 'version': manifest['version'],
            'sha256': hashlib.sha256(Path(path).read_bytes()).hexdigest(),
            'result': 'package structure verified; public-release gates remain separate'}


if __name__ == '__main__':
    try:
        print(json.dumps(verify(sys.argv[1]), indent=2))
    except (IndexError, OSError, ValueError, KeyError, zipfile.BadZipFile) as error:
        sys.exit('Package verification failed: ' + str(error))
