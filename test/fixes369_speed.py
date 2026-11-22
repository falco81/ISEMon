#!/usr/bin/env python3
"""1.10.369: speed on a very large database, round three - the Domain page's
choices (which event numbers and controllers there were) counted ahead of
time with the rest, filled in for the hours counted before by themselves,
and never believed until they are; the long database buttons waited for.

    ./test/fixes369_speed.py
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


folder = Path(tempfile.mkdtemp(prefix='isemon-369-'))
for k, v in dict(STATE_DIR=folder, DB_FILE=folder / 'c.db', BACKUP_DIR=folder / 'b',
                 DUMP_DIR=folder / 'd', RUN_DIR=folder, LOG_DIR=folder,
                 CONFIG_FILE=folder / 'config.json', _LOG_PATH=folder / 'c.log',
                 TOKEN_FILE=folder / 'tok').items():
    setattr(isemon, k, v)
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0, 'winsec': 1, 'winsec_rollup': 1})
store = isemon.Storage(isemon.DB_FILE)
db = store.db
HOUR = 3600
NOW = int(time.time() // HOUR) * HOUR


def events(start, count, at):
    out = []
    for n in range(start, start + count):
        out.append({'ident': 'e%d' % n, 'ts': at + (n % 97) * 600, 'server': 'DC%d' % (n % 3),
                    'event': [4624, 4625, 4769, 4740][n % 4],
                    'kind': ['logon', 'logon-failed', 'kerberos', 'lockout'][n % 4],
                    'account': 'user%d' % (n % 11), 'machine': 'PC%d' % (n % 5),
                    'ip': '10.0.0.%d' % (n % 9), 'is_machine': 1 if n % 13 == 0 else 0})
    return out


def table_shape(since, machines=None, kinds=()):
    """The question asked of the events themselves, as before 1.10.369."""
    was = store.roll_holds
    store.roll_holds = lambda *d: False
    try:
        return store.win_shape(since, machines, kinds)
    finally:
        store.roll_holds = was


def plain(s):
    return (s['counts'], s['events'], sorted(s['servers']))


store.note_win_events(events(0, 600, NOW - 2 * 86400))
store.roll_build_now('test')
store.roll_said(store.ROLL_GOOD, 'test', 1)

print('Counted from nothing: every dimension, the choices among them')
ok('the event numbers and the controllers are held', store.roll_holds('event', 'server'))
for since, mach, kinds in ((NOW - 3 * 86400, None, ()), (NOW - 86400, False, ()),
                           (NOW - 3 * 86400, True, ('logon',)),
                           (NOW - 3 * 86400, None, ('lockout', 'kerberos'))):
    ok('the choices from the counting = from the events (%s, %s, %s)'
       % (int((NOW - since) / 3600), mach, kinds),
       plain(store.win_shape(since, mach, kinds)), plain(table_shape(since, mach, kinds)))

print('A counting made before: the two filled in by themselves')
db.execute("DELETE FROM win_rollup WHERE dim IN ('event', 'server')")
db.commit()
store.set_meta(store.ROLL_HELD, ','.join(isemon.ROLL_DIMS_BEFORE_369))
store._roll_held = (0.0, None)
ok('not held, so not believed', store.roll_holds('event', 'server'), False)
ok('...the page asks the events, and is right',
   plain(store.win_shape(NOW - 3 * 86400)), plain(table_shape(NOW - 3 * 86400)))
ok('...and the check finds nothing wrong with what is held', store.roll_prove(), [])
store.note_win_events(events(600, 200, NOW - 86400))       # written meanwhile
ok('filled in', bool(store.roll_more()), True)
ok('...held now', store.roll_holds('event', 'server'))
ok('...the same choices', plain(store.win_shape(NOW - 3 * 86400)),
   plain(table_shape(NOW - 3 * 86400)))
ok('...and the whole counting still proves', store.roll_prove(), [])

print('An older version ran in between (a downgrade and back)')
said = [{'at': NOW - HOUR, 'dim': 'event', 'val': '4624', 'kind': 'logon', 'mach': 0,
         'quiet': 0, 'told': 0, 'rows': 3, 'bucket': 2}]
store.roll_wrong(said, 'test')
ok('only the two are counted again - the counting stays believed', store.roll_ready())
ok('...not held until they are', store.roll_holds('event', 'server'), False)
ok('...filled in again', bool(store.roll_more()), True)
ok('...and held', store.roll_holds('event', 'server'))
store.roll_wrong([dict(said[0], dim='account', val='user1')], 'test')
ok('anything else disagreeing puts the counting aside, as ever', store.roll_ready(), False)

print('A token search in a window of the past')
OLD = NOW - 10 * 86400
store.add_failed({'session': 'otp/old', 'ts': OLD, 'ip': '198.51.100.9', 'username': 'anna',
                  'kind': 'otp', 'server': 'tok1'})
rows = [('ask-old', OLD - 1, OLD - 1, 'tok1', 'ask', 'anna', '10.1.1.1', 'nas1', 'T',
         'reject', '', '', 'kiosk48', '')]
for n in range(3100):                 # newer packets of the same machine, no attempt beside
    rows.append(('ask-%d' % n, NOW - n * 60, NOW - n * 60, 'tok1', 'ask', 'bob%d' % n,
                 '10.1.1.2', 'nas1', 'T', 'reject', '', '', 'kiosk48', ''))
db.executemany('INSERT INTO otp_asked (ident, ts, at, server, kind, username, ip, nas, tunnel, '
               'verdict, said, session, device, rid) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)', rows)
db.commit()
inner, args = 'oa.device = ?', ['kiosk48']
ok('without a window, the newest packets crowd it out (as it was)',
   'otp/old' in store.otp_asked_sessions('failed', inner, args), False)
ok('in the window asked, the attempt beside its packet is found',
   'otp/old' in store.otp_asked_sessions('failed', inner, args, since=OLD - 3600,
                                         until=OLD + 3600), True)

print('The long database buttons')
page = (ROOT / 'web' / 'index.php').read_text()
api = (ROOT / 'web' / 'isemon-api.php').read_text()
ok('waited for as long as nginx waits', "in_array($what, $long, true) ? 880.0 : 90.0" in page)
ok('...a check, optimize, copy, restore, prune and a database server tried',
   "$long = ['db-check', 'db-optimize', 'db-backup', 'db-restore-kept', 'db-prune'," in page)
ok('one taking longer is not "is isemon.service running?"',
   "if (!empty($GLOBALS['isemon_timed_out'])) {" in api)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
