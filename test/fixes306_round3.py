#!/usr/bin/env python3
"""1.10.306: what the third round of looking for bugs found, fixed.

    ./test/fixes306_round3.py
"""
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
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


src = (ROOT / 'isemon.py').read_text()
web = (ROOT / 'deploy' / 'isemon_web.py').read_text()
inst = (ROOT / 'install.sh').read_text()
page = (ROOT / 'web' / 'index.php').read_text()
api = (ROOT / 'web' / 'isemon-api.php').read_text()

print('Uploads')
ok('a big upload taken from a full admin wholly signed in only, asked before a byte is read',
   (page.count('isemon_full_admin_or_refuse();'), 'function isemon_full_admin_or_refuse(): void'
    in api), (3, True))

print('\nFace ID')
ok('a half sign-in owing a first passkey owes the one made since',
   "if owed == 'enrol' and theirs:" in src)
ok('one\'s own passkey taken away with Face ID whatever name the page came by',
   "'confirm it is you with Face ID, then take it away', 428)" in src)

print('\nThe performance meter')
isemon.LOAD_LAST.update(at=0.0, raw=None, out=None)
isemon.server_load()
raw = dict(isemon.LOAD_LAST['raw'])
raw['at'] -= 3600
isemon.LOAD_LAST.update(at=0.0, raw=raw, out=None)
ok('a reading of an hour ago is no rate', 'cpu' in isemon.server_load(), False)

print('\nThe rest')
ok('the readers of the firewalls\' APIs: none started once stopping',
   'if self.daemon.stopping.is_set():\n                return' in src)
ok('install.sh --log-from: the port closed only once the firewall took a sender',
   ('if (( took > 0 )); then' in inst, 'took none of the senders given' in inst), (True, True))
ok('a change of the network put back with /etc/hosts and the host name',
   ("undo.append(lambda: write_root(HOSTS_FILE, had, 0o644))" in web,
    "'hostnamectl set-hostname (back)'" in web), (True, True))
ok('acme push: a key let go to make room is said', 'was let go to make room for' in src)
print('\nSettings')


def refused(values):
    try:
        isemon.check_settings_together(dict(isemon.DEFAULTS, **values))
        return False
    except ValueError:
        return True
ok('a burst for good no bigger than the bar: refused', refused({'block_lots': 5, 'block_tries': 5}))
ok('...bigger: taken', refused({'block_lots': 50, 'block_tries': 5}), False)
ok('the longest ban shorter than the first: refused',
   refused({'block_max_minutes': 30, 'block_minutes': 60, 'block_ladder': ''}))
ok('...unless a ladder says every length', refused({'block_max_minutes': 30, 'block_minutes': 60,
                                                    'block_ladder': '60, 1440'}), False)
for key in ('mikrotik_list', 'pf_list'):
    try:
        isemon.check_setting(key, '')
        ok('%s emptied: refused' % key, False)
    except ValueError:
        ok('%s emptied: refused' % key, True)
ok('the daemon\'s port not on the page any more',
   ("about:   ['site_name', 'perf_meter', 'debug'," in page, "  'api_port'," in page),
   (True, True))
ok('the longest ban hidden while a ladder is set', "block_max_minutes: ['block_ladder', '']," in page)

print('\nThe page')
ok('the popup for a password set by an administrator: neither its cross nor Escape closes it',
   ("if (MODAL_LOCKED) return;" in page, "if (!MODAL_LOCKED) closeModal();" in page,
    "MODAL_LOCKED = !!must;" in page), (True, True, True))
ok('...and nothing is asked of the daemon behind it', ('if (mustFirst) {' in page,
   "if (typeof ME !== 'undefined' && ME && ME.must_change && !ME.from_dir) return;" in page),
   (True, True))

print('\nThe lists and the whitelist')
import json, shutil, tempfile                       # noqa: E401,E402
work = Path(tempfile.mkdtemp(prefix='isemon-306-'))
try:
    state = work / 'state'
    state.mkdir()
    for k, v in dict(STATE_DIR=state, DB_FILE=state / 'd.db', BACKUP_DIR=state / 'b',
                     DUMP_DIR=state / 'dumps', RUN_DIR=state, LOG_DIR=state,
                     CONFIG_FILE=state / 'config.json', _LOG_PATH=state / 'd.log',
                     TOKEN_FILE=state / 'token').items():
        setattr(isemon, k, v)
    isemon.CONFIG.clear()
    isemon.CONFIG.update(isemon.DEFAULTS)
    isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0})
    (state / 'config.json').write_text(json.dumps({'db_engine': 'sqlite'}))
    store = isemon.Storage(isemon.DB_FILE)
    now = time.time()
    with store.db_write() as db:
        for ip, ts in (('192.0.2.7', now - 86400), ('192.0.2.7', now - 10),
                       ('192.0.2.8', now - 10)):
            db.execute('INSERT INTO block_events (ts, ip, what, why, auto, by) '
                       "VALUES (?, ?, 'blocked', 'x', 1, '')", (ts, ip))
    got = store.blocked_before_many(['192.0.2.7', '192.0.2.8'],
                                    since={'192.0.2.7': now - 10, '192.0.2.8': now - 10})
    ok('banned for the first time: 0 before; twice: 1 before', got,
       {'192.0.2.7': 1, '192.0.2.8': 0})
    ok('...and without the ban it has now, every ban counted',
       store.blocked_before_many(['192.0.2.7']), {'192.0.2.7': 2})
    store.add_whitelist('192.0.2.9', 'the office printer', 'admin')
    store.add_whitelist('192.0.2.9', '', 'admin')
    ok('whitelisted again without a note keeps its note',
       [r['note'] for r in store.whitelist() if r['ip'] == '192.0.2.9'], ['the office printer'])
    store.add_whitelist('192.0.2.9', 'the new printer', 'admin')
    ok('...a new note replaces it',
       [r['note'] for r in store.whitelist() if r['ip'] == '192.0.2.9'], ['the new printer'])
    q = isemon.ListQuery('failed', '"novak"')
    ok('a word in quotes is the word', (q.words, q.sql), ('novak', ''))
    q = isemon.ListQuery('failed', '"jan novak"')
    ok('...a phrase in quotes the phrase', q.words, 'jan novak')
    ok('...no quotes: as it always was', isemon.ListQuery('failed', 'novak').words, 'novak')
finally:
    shutil.rmtree(str(work), ignore_errors=True)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
