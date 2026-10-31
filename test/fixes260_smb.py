#!/usr/bin/env python3
"""1.10.260: backups to a Windows or Samba share - smbclient said "Could not
determine network interfaces, you must use a interfaces config line": the
service kept it from reading them (AF_NETLINK not among its address families).
The unit lets it now; an smbclient that says so anyway is told in words.

    ./test/fixes260_smb.py
"""
import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import isemon                                        # noqa: E402

PASS = FAIL = 0


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


unit = (ROOT / 'deploy' / 'isemon.service').read_text()
line = [l for l in unit.splitlines() if l.startswith('RestrictAddressFamilies=')]
ok('the daemon\'s unit lets smbclient read the network interfaces (AF_NETLINK)',
   line and 'AF_NETLINK' in line[0].split('=', 1)[1].split())
ok('...and nothing more than it had besides', sorted(line[0].split('=', 1)[1].split()),
   sorted(['AF_INET', 'AF_INET6', 'AF_UNIX', 'AF_NETLINK']))
ok('install.sh puts the unit in on an upgrade',
   'run install -D -m 0644 "$SOURCE_DIR/deploy/isemon.service" "$UNIT_FILE"'
   in (ROOT / 'install.sh').read_text())

work = Path(tempfile.mkdtemp(prefix='isemon-260-'))
try:
    fake = work / 'smbclient'
    fake.write_text('#!/bin/sh\necho "ERROR: Could not determine network interfaces, you must '
                    'use a interfaces config line" >&2\nexit 1\n')
    fake.chmod(0o755)
    os.environ['ISEMON_RB_SMBCLIENT'] = str(fake)
    smb = isemon.RbSmb({'host': 'nas.example.cz', 'share': 'backup', 'port': 445,
                        'user': 'u', 'path': 'isemon'})
    try:
        smb.open()
        ok('an smbclient kept from the interfaces: refused', False)
    except isemon.RbError as e:
        ok('an smbclient kept from the interfaces: said what to do',
           ('network interfaces' in str(e), 'install.sh --upgrade' in str(e)), (True, True))
    finally:
        smb.close()
finally:
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
