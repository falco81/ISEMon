#!/usr/bin/env python3
"""release.py - sign a release folder, then pack it (isemon 1.10.222).

    tools/release.py FOLDER KEY [OUT.tar.gz]

FOLDER is the unpacked isemon-X.Y.Z; KEY the Ed25519 private key of a
release key whose public half is in deploy/release-keys/. It writes MANIFEST
(the SHA-256 of every file, one per line, sorted) and MANIFEST.sig (the
Ed25519 signature of MANIFEST, by openssl), and packs the folder as
OUT (isemon-X.Y.Z.tar.gz beside the folder by default).

An upgrade from the pages (Settings -> Upgrades) takes only a package whose
MANIFEST is signed by a key the server trusts, whose every file is the one
listed and which holds nothing else: no link, no device, no path outside
its one folder. install.sh --upgrade on the command line asks none of this.

The private key is never in the package and never on the server.
"""
import hashlib
import os
import subprocess
import sys
import tarfile


def manifest(folder):
    lines = []
    for top, dirs, files in os.walk(folder):
        dirs[:] = sorted(d for d in dirs if d != '__pycache__')
        for name in sorted(files):
            path = os.path.join(top, name)
            rel = os.path.relpath(path, folder).replace(os.sep, '/')
            if rel in ('MANIFEST', 'MANIFEST.sig') or name.endswith('.pyc'):
                continue
            if os.path.islink(path) or not os.path.isfile(path):
                raise SystemExit('%s is not a plain file - a package holds plain files only' % rel)
            h = hashlib.sha256()
            with open(path, 'rb') as f:
                for lump in iter(lambda: f.read(1 << 20), b''):
                    h.update(lump)
            lines.append('%s  %s' % (h.hexdigest(), rel))
    return '\n'.join(sorted(lines, key=lambda l: l[66:])) + '\n'


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    folder, key = os.path.abspath(argv[0]), argv[1]
    out = argv[2] if len(argv) > 2 else folder.rstrip('/') + '.tar.gz'
    man = os.path.join(folder, 'MANIFEST')
    with open(man, 'w', encoding='utf-8') as f:
        f.write(manifest(folder))
    subprocess.run(['openssl', 'pkeyutl', '-sign', '-inkey', key, '-rawin', '-in', man,
                    '-out', os.path.join(folder, 'MANIFEST.sig')], check=True)
    pubs = os.path.join(folder, 'deploy', 'release-keys')
    good = []
    for name in sorted(os.listdir(pubs)) if os.path.isdir(pubs) else []:
        if name.endswith('.pub') and subprocess.run(
                ['openssl', 'pkeyutl', '-verify', '-pubin', '-inkey', os.path.join(pubs, name),
                 '-rawin', '-in', man, '-sigfile', os.path.join(folder, 'MANIFEST.sig')],
                capture_output=True).returncode == 0:
            good.append(name)
    if not good:
        raise SystemExit('the signature is by no key in deploy/release-keys/ - the package would '
                         'be refused on the pages')
    top = os.path.basename(folder.rstrip('/'))

    def plain(info):
        info.uid = info.gid = 0
        info.uname = info.gname = 'root'
        if '__pycache__' in info.name or info.name.endswith('.pyc'):
            return None
        return info
    with tarfile.open(out, 'w:gz') as tar:
        tar.add(folder, arcname=top, filter=plain)
    print('%s: MANIFEST of %d files, signed (%s)' % (out, manifest(folder).count('\n'),
                                                     ', '.join(good)))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
