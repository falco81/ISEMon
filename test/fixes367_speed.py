#!/usr/bin/env python3
"""1.10.367: speed on a very large database, round one - the indexes that were
missing and the questions that could not use one, each kept as it is now
asked. Measured on PostgreSQL and SQLite with millions of made-up rows; here
the plans are checked on SQLite.

    ./test/fixes367_speed.py
"""
import sys
import tempfile
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


folder = Path(tempfile.mkdtemp(prefix='isemon-367-'))
for k, v in dict(STATE_DIR=folder, DB_FILE=folder / 'c.db', BACKUP_DIR=folder / 'b',
                 DUMP_DIR=folder / 'd', RUN_DIR=folder, LOG_DIR=folder,
                 CONFIG_FILE=folder / 'config.json', _LOG_PATH=folder / 'c.log',
                 TOKEN_FILE=folder / 'tok').items():
    setattr(isemon, k, v)
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0})
store = isemon.Storage(isemon.DB_FILE)
db = store.db


def plan(sql, args=()):
    return ' | '.join(str(r[3]) for r in db.execute('EXPLAIN QUERY PLAN ' + sql, args))


print('The indexes')
names = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type = 'index'")}
for n in ('failed_asked_as', 'passed_asked_as', 'events_level_ts', 'passed_acl_kind_ts',
          'blocked_log_country', 'fw_kept_type_ts', 'fw_nat_action_ts', 'win_bad_ts'):
    ok('%s is there' % n, n in names)

print('The questions')
ok('the row count guessed by two seeks, never a whole index read',
   'SCAN failed' in plan('SELECT (SELECT MAX(rowid) FROM failed) AS hi, (SELECT MIN(rowid) '
                         'FROM failed) AS lo'), False)
ok('...as the code asks it', 'SELECT (SELECT MAX(rowid) FROM {0}) AS hi'
   in (ROOT / 'isemon.py').read_text())
ok('an address clicked: both sides of the OR by an index',
   'failed_asked_as' in plan('SELECT * FROM failed WHERE ts > ? AND (ip = ? OR asked_as IN (?))',
                             (1, 'x', 'y')))
ok('one level of the events, newest first, without a sort',
   plan('SELECT * FROM events WHERE level = ? ORDER BY ts DESC LIMIT 50', ('warn',)),
   'SEARCH events USING INDEX events_level_ts (level=?)')
ok('the watch list: the VPN\'s refusals alone, by the index',
   'failed_kind_ts' in plan("SELECT COUNT(*) FROM failed WHERE ts >= ? AND (kind = 'vpn' OR "
                            "kind IS NULL)", (1,)))
ok('the firewall\'s own lines newest first, by (type, ts)',
   'fw_kept_type_ts' in plan("SELECT * FROM fw_events WHERE ts >= ? AND type = 'event' AND "
                             "brief = 0 ORDER BY ts DESC LIMIT 60", (1,)))
ok('the dst-nat rules\' lines by (action, ts)',
   'fw_nat_action_ts' in plan("SELECT * FROM fw_events WHERE area = 'nat' AND action = 'dstnat' "
                              "AND ts >= ?", (1,)))

print('The catalogue takes in the countries')
for n in range(30):
    store.add_failed({'session': 'f/%d' % n, 'ts': time.time() - n * 60,
                      'ip': '198.51.100.%d' % n, 'username': 'user%d' % (n % 5),
                      'kind': 'vpn', 'country': ['CZ', 'DE', 'PL'][n % 3]})
store.seen_flush()
ok('filled', store.seen_build(), True)
ok('...with the countries', store.seen_usable('failed', 'country'), True)
ok('...and they are what the table holds', sorted(store.seen_values_of('failed', 'country')),
   ['CZ', 'DE', 'PL'])
# A catalogue filled by an older version: no countries in it.
db.execute("DELETE FROM seen_values WHERE col = 'country'")
store.drop_meta('seen_wanted')
store._seen_filled = (0.0, None)
ok('one filled before: its countries are not believed', store.seen_usable('failed', 'country'),
   False)
ok('...the rest still are', store.seen_usable('failed', 'username'), True)
ok('the countries alone are filled in', store.seen_build(), True)
ok('...and believed after', store.seen_usable('failed', 'country'), True)
ok('...the same values', sorted(store.seen_values_of('failed', 'country')), ['CZ', 'DE', 'PL'])

print('The rest')
src = (ROOT / 'isemon.py').read_text()
ok('a person\'s card never waits for the VPN list to be put together',
   'for c in (self.fw_vpn_now(wait=False).get(\'clients\') or [])' in src)
ok('the file\'s pages by table kept an hour', 'STORE_DBSTAT[key] = (time.time(), rows)' in src)
page = (ROOT / 'web' / 'index.php').read_text()
ok('the Domain page\'s own refresh waits for an answer still out',
   "if (WPAGE_SHOWN === 'events') loadWinEvents(); else loadWindows(true);" in page)
ok('a router\'s history kept beside another\'s', "if (k.indexOf(r.name + '|') === 0) delete "
   "TR_HIST_DATA[k];" in page)
ok('an hour\'s label with its minutes (+5:30)',
   "pad2(dd.getHours()) + ':' + pad2(dd.getMinutes());" in page)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
