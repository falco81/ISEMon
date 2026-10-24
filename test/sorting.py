#!/usr/bin/env python3
"""Ordering a list by a heading, on the server.

Every long list the server pages through - the refusals, the logins, the
domain's events, the ban history, the daemon's own events, the firewall's
lines - can be ordered by pressing a heading. What is pressed reaches the
statement only through a list of what each list may be ordered by, blanks go
last whichever way round, and a table too big to order whole is ordered among
its newest rows.

    ./test/sorting.py
"""
import shutil
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import isemon                                        # noqa: E402

PAGE_SRC = (HERE.parent / 'web' / 'index.php').read_text(encoding='utf-8')
PASS = FAIL = 0


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


def title(words):
    print('\n%s' % words)


folder = tempfile.mkdtemp(prefix='isemon-sort-')
isemon.STATE_DIR = Path(folder)
isemon.DB_FILE = Path(folder) / 's.db'
isemon.LOG_DIR = isemon.RUN_DIR = Path(folder)
isemon._LOG_PATH = Path(folder) / 's.log'
isemon.CONFIG.update({'blacklist': 0, 'geo': 0, 'mikrotik_host': '', 'debug': False,
                      'ise': 0, 'winsec': 0, 'otp': 0, 'eduroam': 0, 'tacplus': 0, 'nps': 0})
store = isemon.Storage(isemon.DB_FILE)
now = time.time()

title('The refusals')
for n, (user, reason, ip) in enumerate((('novak', 'wrong password', '203.0.113.7'),
                                        ('', 'no such user', '203.0.113.20'),
                                        ('adam', 'locked', '198.51.100.3'),
                                        ('zelda', 'wrong password', '192.0.2.1'))):
    store.add_failed({'session': 's%d' % n, 'ts': now - 100 + n, 'server': 'ise1', 'ip': ip,
                      'username': user, 'reason': reason, 'kind': 'vpn', 'device': 'fw',
                      'detail': ''})
rows, _ = store.failed_rows(sort='username', desc=False)
ok('ordered by the name, A to Z, with nobody last', [r['username'] for r in rows],
   ['adam', 'novak', 'zelda', ''])
rows, _ = store.failed_rows(sort='username', desc=True)
ok('...and Z to A, nobody still last', [r['username'] for r in rows],
   ['zelda', 'novak', 'adam', ''])
rows, _ = store.failed_rows(sort='reason', desc=False)
ok('...by why it failed, with the newest first among the same reason',
   [r['session'] for r in rows], ['s2', 's1', 's3', 's0'])
rows, _ = store.failed_rows()
ok('...and with nothing pressed, newest first as it always was',
   [r['session'] for r in rows], ['s3', 's2', 's1', 's0'])
rows, _ = store.failed_rows(sort="username; DROP TABLE failed", desc=False)
ok('a heading that is not on the list is the time, and nothing else',
   [r['session'] for r in rows], ['s3', 's2', 's1', 's0'])
ok('...and the table is still there', store.failed_rows()[1], 4)

title('The ban history and the daemon\'s events')
for ip in ('203.0.113.9', '198.51.100.4'):
    store.block(ip, None, 'a test ban of %s' % ip)
store.unblock('203.0.113.9', how='taken off', by='a test')
rows, _ = store.blocked_history(sort='ip', desc=False)
ok('the ban history by address', [r['ip'] for r in rows], ['198.51.100.4', '203.0.113.9'])
rows, _ = store.blocked_history(sort='ended', desc=True)
ok('...by when it ended, the ones still on counted as not ended yet',
   [r['ip'] for r in rows], ['198.51.100.4', '203.0.113.9'])
rows, _ = store.blocked_history(sort='by', desc=False)
ok('...and by who, a word MariaDB keeps for itself', len(rows), 2)
store.add_event('zeta', 'something', who='b')
store.add_event('alpha', 'else', who='a')
rows, _ = store.events(sort='kind', desc=False)
ok('the daemon\'s events by kind', [r['kind'] for r in rows][:1], ['alpha'])

title('A table too big to order whole')
ok('is ordered among its newest rows, and says how many', isemon.SORT_WINDOW, 50000)
sql, _ = isemon.sorted_newest('SELECT a', ' FROM t WHERE 1=1', [],
                              isemon.order_by('ip', True, {'ip': 'ip'}), ' LIMIT 1')
ok('...the newest by the time first, then the heading',
   'ORDER BY ts DESC LIMIT 50000) AS newest ORDER BY' in sql, True)

title('The page')
ok('every server list asks with its heading',
   all(('sortArgs(SORTS.%s)' % k) in PAGE_SRC for k in ('failed', 'passed', 'win', 'events',
                                                         'past')), True)
ok('...and Clear puts it back to the time',
   PAGE_SRC.count('sortReset(SORTS.') >= 5, True)
ok('every other table is ordered where it stands',
   'markSortableTables(host)' in PAGE_SRC, True)

shutil.rmtree(folder, ignore_errors=True)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
