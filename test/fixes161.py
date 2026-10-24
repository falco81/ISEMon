#!/usr/bin/env python3
"""1.10.161: a firewall filed a file per kind of message, shown one row per
folder in `isemon --status` and on the Logs page - the same folding in both.

    ./test/fixes161.py
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
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


NOW = 1_800_000_000.0
DAY = 86400.0


def tail(path, source='fwlog', at=NOW - 60, records=10, behind=0, **more):
    one = {'path': path, 'kind': source, 'source': source, 'at': at, 'records': records,
           'behind': behind, 'size': 100, 'error': '', 'says': '', 'there': True,
           'ahead': 0, 'day': None}
    one.update(more)
    return one


logs = [tail('/var/log/remote/isea/CISE_Failed_Attempts.log', source='ise', records=5)]
for i in range(6):
    logs.append(tail('/var/log/remote/fw1.example.org/%%FTD-6-30201%d.log' % i,
                     records=100 + i, behind=10 * i,
                     at=(NOW - 60) if i < 4 else (0 if i == 4 else NOW - 30 * DAY)))
logs.append(tail('/var/log/remote/fw1.example.org/%FTD-4-106023.log', records=7,
                 error='[Errno 13] Permission denied', says='this daemon may not read it'))
for i in range(2):
    logs.append(tail('/var/log/remote/fw2.example.org/%%FTD-6-30201%d.log' % i, records=3))
logs.append(tail('/var/log/remote/pdc1/WinSecurity.log', source='winsec', records=9))

print('\nThe files of one firewall, folded into one row per folder')
rows = isemon.log_rows_grouped(logs, NOW, 14 * DAY)
paths = [r['path'] for r in rows]
ok('the ISE file keeps its row', '/var/log/remote/isea/CISE_Failed_Attempts.log' in paths)
ok('six files of one folder are one row', '/var/log/remote/fw1.example.org/' in paths)
folder = [r for r in rows if r.get('files')][0]
ok('...that counts them', folder['files'], 6)
ok('...adds up what they hold', folder['records'], sum(100 + i for i in range(6)))
ok('...and what is still to read', folder['behind'], sum(10 * i for i in range(6)))
ok('...says when the newest was read', folder['at'], NOW - 60)
ok('...and how many are quiet (never, or not for longer than kept)', folder['quiet'], 2)
ok('a file that may not be read keeps a row of its own',
   '/var/log/remote/fw1.example.org/%FTD-4-106023.log' in paths)
ok('two files of a folder are not folded',
   sum(1 for p in paths if p.startswith('/var/log/remote/fw2.example.org/%')), 2)
ok('the domain controller keeps its row', '/var/log/remote/pdc1/WinSecurity.log' in paths)
ok('the order of the list is kept', paths[0], '/var/log/remote/isea/CISE_Failed_Attempts.log')
ok('--files lists every one', isemon.log_rows_grouped(logs, NOW, 14 * DAY, every=True), logs)

print('\nThe page folds them the same way')
node = shutil.which('node')
page = (HERE.parent / 'web' / 'index.php').read_text(encoding='utf-8')


def js_function(name):
    at = page.index('\nfunction %s(' % name) + 1
    return page[at:page.index('\n}', at) + 2]


if node:
    script = ('var LOG_GROUP_AT = 4;\n' + js_function('logTroubled') + '\n'
              + js_function('logRowsGrouped') + '\n'
              + 'var logs = %s;\n' % json.dumps(logs)
              + 'console.log(JSON.stringify(logRowsGrouped(logs, %r, %r).map(function (r) {'
                ' return [r.path, r.files || 0, r.records, r.behind, r.quiet || 0]; })));'
              % (NOW, 14 * DAY))
    got = json.loads(subprocess.run([node, '-e', script], capture_output=True, text=True,
                                    check=True).stdout)
    want = [[r['path'], r.get('files') or 0, r['records'], r['behind'], r.get('quiet') or 0]
            for r in rows]
    ok('the same rows, the same sums', got, want)
else:
    print('  (no node here: the page\'s own function is not run)')

print('\nWho has been busy')
src = (HERE.parent / 'isemon.py').read_text(encoding='utf-8')
ok('a firewall\'s folder is not counted as a machine that authenticates',
   "t.get('source') not in ('winsec', 'fwlog')" in src)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
