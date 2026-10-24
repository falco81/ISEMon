#!/usr/bin/env python3
"""The catalogue of values: the same answers as the tables, from a small table.

The search box and the drop-downs over the lists ask `seen_values` once it
is filled (1.10.98). Every one of them is asked here twice - of the tables,
as every version before did, and of the catalogue - over the same rows, and
the answers compared. Rows that were there before the catalogue existed are
filled in from the tables (`seen_build`); rows written after it go in as
they are written (`seen_note` / `seen_flush`). Both halves are here.

    ./test/catalogue.py
"""
import random
import shutil
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import isemon  # noqa: E402

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
    print('\n' + words)


folder = tempfile.mkdtemp(prefix='isemon-catalogue-')
isemon.STATE_DIR = Path(folder)
isemon.DB_FILE = Path(folder) / 'catalogue.db'
isemon.LOG_DIR = Path(folder)
isemon._LOG_PATH = Path(folder) / 'catalogue.log'
store = isemon.Storage()
rng = random.Random(11)
NOW = time.time()
NAMES = ['jnovak', 'jana.nova', 'petr.kolar', 'admin', 'svc-backup', 'Novotny', 'eva.k',
         'host/NTB-04.example.cz', 'zero.client']
DEVICES = ['SW_B1_SW1_STACK', 'SW_B2_SW3_SOC', 'FTD-VPN', 'AP-MASTER', 'sw-core-1']
MACS = ['00-30-04-13-A9-%02X' % n for n in range(12)]
KINDS_F = ['vpn', 'nps-mab-lan', 'nps-dot1x-lan', 'tacacs', 'dot1x-wifi', None]
KINDS_P = ['vpn', 'nps-mab-lan', 'nps-dot1x-lan', 'tacacs-cmd', 'dot1x-wifi']
REASONS = ['wrong password', 'no policy matched', 'the EAP exchange failed', '']
PORTS = ['GigabitEthernet1/0/%d' % n for n in range(1, 9)]


def some_rows(start, count, when):
    for n in range(start, start + count):
        ts = when - rng.random() * 86400 * 20
        name = rng.choice(NAMES)
        store.add_failed({'session': 'f/%d' % n, 'ts': ts, 'ip': '198.51.100.%d' % rng.randrange(40),
                          'username': name, 'kind': rng.choice(KINDS_F),
                          'device': rng.choice(DEVICES), 'server': 'ise%d' % rng.randrange(1, 3),
                          'mac': rng.choice(MACS + ['']), 'port': rng.choice(PORTS + ['']),
                          'client': '10.0.%d.%d' % (rng.randrange(3), rng.randrange(9)),
                          'reason': rng.choice(REASONS), 'tunnel': rng.choice(['SITE-A', 'SITE-B', ''])})
        kind = rng.choice(KINDS_P)
        store.add_passed({'session': 'p/%d' % n, 'ts': ts, 'ip': '192.0.2.%d' % rng.randrange(40),
                          'username': rng.choice(NAMES), 'kind': kind,
                          'device': rng.choice(DEVICES), 'server': 'ise%d' % rng.randrange(1, 3),
                          'mac': rng.choice(MACS + ['']), 'port': rng.choice(PORTS + ['']),
                          'client': '10.0.%d.%d' % (rng.randrange(3), rng.randrange(9)),
                          'profile': rng.choice(['VPN-Staff', 'VPN-IT', 'MAB-Printers']),
                          'policy': rng.choice(['Default', 'Wired', '']),
                          'tkey': rng.choice(['607|LAN_Odbor', '5', 'VLAN4', '']),
                          'cmd': ('show running-config' if kind == 'tacacs-cmd'
                                  else ''),
                          'groups': rng.choice(['VPN, Staff', 'Staff', ''])})


# Rows that were there before the catalogue existed.
some_rows(0, 400, NOW - 86400)
with store._seen_lock:
    store._seen_pending = {}          # an older version kept no catalogue
ok('before it is filled, nothing is asked of it', store.seen_ready(), False)


def answers():
    """Everything the catalogue answers for, asked as the page asks it."""
    out = {}
    for word in ('no', 'jn', 'nova', 'svc', 'ntb-04'):
        out['names/' + word] = sorted(
            (n['name'], n['tries'], n['signed_in'], n['addresses'], n['last'])
            for n in store.find_names(word, 40))
    for word in ('00-30-04', '0030 0413', '10.0.1', 'SW_B', 'sw-', 'running', 'ftd'):
        got = store.find_more(word, 40)
        out['more/' + word] = {k: sorted((o['said'], o['failed'], o['passed'], o['last'],
                                          tuple(o['kinds']))
                                         for o in v) for k, v in got.items()}
    for table in ('failed', 'passed'):
        for column in ('device', 'server'):
            out['distinct/%s/%s' % (table, column)] = store._distinct_now(table, column, 60)
            out['distinct/%s/%s/nps' % (table, column)] = store._distinct_now(
                table, column, 60, ('nps-mab-lan', 'nps-dot1x-lan'))
    for table, name in (('failed', 'port'), ('failed', 'reason'), ('failed', 'tunnel'),
                        ('passed', 'profile'), ('passed', 'policy'), ('passed', 'vlan'),
                        ('passed', 'group'), ('passed', 'client')):
        column = store.PICK_COLUMNS[name]
        for kinds in ((), ('nps-mab-lan', 'nps-dot1x-lan'), ('vpn',)):
            out['pick/%s/%s/%s' % (table, name, kinds)] = store._pick_values_now(
                table, name, column, kinds)
    return out


title('Filled from the rows already there')
fromTables = answers()
ok('it fills itself from the rows', store.seen_build(), True)
ok('...and is believed from then on', store.seen_ready(), True)
fromCatalogue = answers()
for key in sorted(fromTables):
    ok('%s: the same answer' % key, fromCatalogue[key], fromTables[key])
ok('(the catalogue is a fraction of the rows)',
   store.db.execute('SELECT COUNT(*) AS n FROM seen_values').fetchone()['n']
   < 2 * (store.rows_in('failed') + store.rows_in('passed')), True)

title('...and kept as rows are written')
some_rows(1000, 300, NOW)
store.seen_flush()
store._seen_said = (0.0, '')
withNew = answers()
store.set_meta('seen_state', 'off-for-the-check')
store._seen_said = (0.0, '')
tablesNew = answers()
store.set_meta('seen_state', 'ready')
store._seen_said = (0.0, '')
for key in sorted(tablesNew):
    ok('%s: still the same answer' % key, withNew[key], tablesNew[key])

title('A value longer than the catalogue keeps sends that column back to the table')
store.add_failed({'session': 'long/1', 'ts': NOW, 'ip': '198.51.100.1', 'username': 'x',
                  'kind': 'vpn', 'reason': 'r' * 300})
store.seen_flush()
ok('the column is marked', store.seen_is_long('failed', 'reason'), True)
ok('...and asked of the table, where the long value is',
   any(len(v) == 300 for v in store._distinct_now('failed', 'reason', 60)), True)

title('What changes values already stored empties it and fills it again')
store.seen_reset('a check')
ok('emptied, it is not believed', store.seen_ready(), False)
ok('...and is empty', store.db.execute('SELECT COUNT(*) AS n FROM seen_values')
   .fetchone()['n'], 0)
ok('...until it is filled again', store.seen_build(), True)
again = answers()
store.set_meta('seen_state', 'off-for-the-check')
store._seen_said = (0.0, '')
tablesAgain = answers()
store.set_meta('seen_state', 'ready')
store._seen_said = (0.0, '')
ok('...with the same answers as the tables', again == tablesAgain, True)

title('Values whose rows have all gone are let go')
with store.db_write() as db:
    db.execute("DELETE FROM failed WHERE username = 'svc-backup'")
    db.execute("DELETE FROM passed WHERE username = 'svc-backup'")
    db.execute("DELETE FROM failed WHERE kind = 'tacacs'")
ok('some are', store.seen_prune() > 0, True)
ok('...a door with no rows left at all is gone from it', store.db.execute(
    "SELECT COUNT(*) AS n FROM seen_values WHERE tbl = 'failed' AND kind = 'tacacs'")
   .fetchone()['n'], 0)

store.db.close()
shutil.rmtree(folder, ignore_errors=True)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
