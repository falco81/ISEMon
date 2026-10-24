#!/usr/bin/env python3
"""1.10.188: bans that ran out are not charged twice, folded subnets come
apart the way they went together, the logs are read for what they say, and
the database's upkeep finishes what it starts.

    ./test/fixes188.py
"""
import gzip
import json
import os
import random
import shutil
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

# The ban feed's own setup - a store, a daemon, NPS lines for a VPN - is the
# shape every test of the judging needs; borrowed rather than copied.
_src = (HERE / 'banfeed.py').read_text(encoding='utf-8')
_g = {'__name__': 'borrowed', '__file__': str(HERE / 'banfeed.py')}
exec(compile(_src[:_src.index('NOW = time.time() - 600')], 'banfeed', 'exec'), _g)
isemon = _g['isemon']
fresh, vpn_try, take, FOLDERS = _g['fresh'], _g['vpn_try'], _g['take'], _g['FOLDERS']

PASS = FAIL = 0
PORT = 19000 + random.randint(0, 900)


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


source = (HERE.parent / 'isemon.py').read_text(encoding='utf-8')

print('\nA ban that has run out but is not swept yet')
store, daemon = fresh()
isemon.CONFIG.update({'block_tries': 3, 'block_window_min': 60,
                      'block_ladder': '15, 60, forever', 'block_mode': 'temporary'})
now = time.time()
ip = '203.0.113.50'
take(daemon, sum((vpn_try(now - 30 + i, 'u%d' % i, ip) for i in range(3)), []))
ok('three refusals ban it', store.blocked_one(ip) is not None, True)
with store.db_write() as db:
    db.execute('UPDATE blocked SET until=? WHERE ip=?', (time.time() - 1, ip))
store.memo_clear(ip)
take(daemon, vpn_try(now + 1, 'z', ip))
row = store.blocked_one(ip)
ok('one more attempt does not charge the three again, a rung higher',
   row is not None and float(row['until']) <= time.time(), True)
daemon.store.sweep_expired()
ok('a ban swept late is written as ending when it ran out, not when it was noticed',
   float(store.db.execute("SELECT MAX(ts) AS ts FROM block_events WHERE ip=? "
                          "AND what='let back in'", (ip,)).fetchone()['ts']) < time.time() - 0.5,
   True)
ok('...so what was read in between is counted from then',
   store.let_back_in_at(ip) is not None and store.let_back_in_at(ip) < time.time() - 0.5, True)

print('\nFolded subnets')
store, daemon = fresh()
isemon.CONFIG.update({'fold_least': 2, 'fold_widest': 24})
for i in range(1, 5):
    daemon.ban('192.0.2.%d' % i, why='x')
folded = daemon.fold_apply()
ok('four bans folded into one subnet', [r['ip'] for r in store.blocked_all()], ['192.0.2.0/24'])
ok('...under a number that can be found again, on every engine',
   (int(folded['version']) >= 1,
    store.fold_version(folded['version']) is not None), (True, True))
daemon.unban(None)
ok('letting everybody in takes the subnet’s list of members too',
   store.get_meta('blocked_members_192.0.2.0/24'), '')
daemon.whitelist_add('192.0.2.3')
daemon.fold_undo(folded['version'])
ok('...so undoing the folding afterwards brings nobody back', store.blocked_all(), [])
store, daemon = fresh()
for i in range(1, 5):
    daemon.ban('192.0.2.%d' % i, why='x')
folded = daemon.fold_apply()
daemon.whitelist_add('192.0.2.3')
daemon._spare_from = None
daemon.fold_undo(folded['version'])
ok('an address whitelisted since is not put back by an undo',
   sorted(r['ip'] for r in store.blocked_all()), ['192.0.2.1', '192.0.2.2', '192.0.2.4'])

print('\nA subnet let go as somebody typed it')
store, daemon = fresh()
for i in range(1, 5):
    daemon.ban('192.0.2.%d' % i, why='x')
daemon.fold_apply()
daemon.add_user('boss', 'a-long-enough-password', 'fulladmin', by='test')
isemon.CONFIG['api_port'] = PORT
api = isemon.ApiServer(daemon, PORT)
api.start()
time.sleep(0.4)


def call(path, payload=None, session=None):
    req = urllib.request.Request('http://127.0.0.1:%d%s' % (PORT, path),
                                 data=json.dumps(payload).encode() if payload is not None
                                 else None, method='POST' if payload is not None else 'GET')
    req.add_header('X-Isemon-Token', isemon.API_TOKEN)
    if session:
        req.add_header('X-Isemon-Session', session)
    if payload is not None:
        req.add_header('Content-Type', 'application/json')
    try:
        with urllib.request.urlopen(req, timeout=60) as answer:
            return answer.status, json.loads(answer.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or '{}')


try:
    token = call('/api/auth/login', {'name': 'boss',
                                     'password': 'a-long-enough-password'})[1]['token']
    call('/api/blocked', {'remove': '192.0.2.7/24'}, session=token)
    ok('`192.0.2.7/24` takes the subnet apart: every member back on its own',
       sorted(r['ip'] for r in store.blocked_all()),
       ['192.0.2.1', '192.0.2.2', '192.0.2.3', '192.0.2.4'])
finally:
    api.stop() if hasattr(api, 'stop') else None

print('\nThe router')
ok('`4m59s990ms` is five minutes, not seventeen hours',
   (isemon.mikrotik_seconds('4m59s990ms'), isemon.mikrotik_seconds('500ms'),
    isemon.mikrotik_seconds('1d2h3m4s')), (299, 0, 93784))
store, daemon = fresh()
daemon.ban('203.0.113.7', minutes=10, why='x')
daemon.ban('203.0.113.8', minutes=10, why='x')
with store.db_write() as db:
    db.execute('UPDATE blocked SET until=? WHERE ip=?', (time.time() - 5, '203.0.113.7'))
ok('a ban that has run out is not put on the router again for a minute',
   [r['ip'] for r in daemon._blocked_for_router()], ['203.0.113.8'])

print('\nThe domain’s accounts expected to read it whole')
ok('an account is not cut at a dot', [isemon.win_account_name(x) for x in (
    'svc.adsync', 'CORP\\svc.adsync', 'jan@corp.int', '*.sync')],
   ['svc.adsync', 'svc.adsync', 'jan', '*.sync'])
ok('...a machine still is', [isemon.win_account_name(x) for x in (
    'BDCX02$', 'CORP\\BDCX02$', 'host/bdcx02@CORP.INT')], ['bdcx02', 'bdcx02', 'bdcx02'])
isemon.WIN_EXPECTED.clear()
isemon.WIN_EXPECTED.add('svc.adsync')
isemon.WIN_CONTROLLERS.add('bdcx02')
ok('a controller is still itself written as its full name',
   (isemon.win_is_expected('bdcx02.corp-example.int'), isemon.win_is_expected('BDCX02$')),
   (True, True))
isemon.WIN_CONTROLLERS.discard('bdcx02')
ok('`svc.adsync` expected excuses itself and not `svc.helpdesk`',
   (isemon.win_is_expected('CORP\\svc.adsync'), isemon.win_is_expected('CORP\\svc.helpdesk')),
   (True, False))
isemon.WIN_EXPECTED.clear()

print('\nThe hour the clocks go back, one file at a time')
last = isemon._LastBySource()
isemon._READING_FROM.source = 'dc.log'
last['ts'] = 100.0
isemon._READING_FROM.source = 'ftd.log'
ok('each file remembers its own line before', last.get('ts'), 0.0)
isemon._READING_FROM.source = 'dc.log'
ok('...and keeps it', last.get('ts'), 100.0)
isemon._READING_FROM.source = ''

print('\nA log copied and truncated, with yesterday’s compressed after')
folder = Path(tempfile.mkdtemp(prefix='isemon-188-'))
FOLDERS.append(str(folder))
live = folder / 'a.log'
read = b''.join(b'line %03d\n' % n for n in range(40))
live.write_bytes(read)
tail = isemon.LogTail(str(live))
list(tail.read())
(folder / 'a.log.1').write_bytes(read + b'unread1\nunread2\n')
with gzip.open(str(folder / 'a.log.2.gz'), 'wb') as f:
    f.write(b''.join(b'y%03d older\n' % n for n in range(80)))
os.utime(str(folder / 'a.log.1'), (time.time() - 30, time.time() - 30))
ok('the plain copy that is ours is chosen over a newer compressed one',
   tail._rotated_in(str(live)), str(folder / 'a.log.1'))

print('\nISE records in parts')
hold = {}
head = 'Oct 14 10:00:00 ise1 CISE_Failed_Attempts 0000000777 3 %d '
body = ('2026-10-14 10:00:00.000 +02:00 0000012345 5400 NOTICE Failed-Attempt: '
        'Authentication failed, ConfigVersionId=1, ')
isemon.ise_parse_lines([head % 1 + 'UserName=OLDGUY, Calling-Station-ID=9.9.9.9, '], hold)
for slot in hold.values():
    slot['at'] = 0
got = isemon.ise_parse_lines([head % 0 + body, head % 2 + 'UserName=new, x=y'], hold)
ok('a part of a record days old is not joined to a new one', got, [])
ok('...and is let go however few are waiting', len(hold), 1)
hold = {}
isemon.ise_parse_lines([head % 0 + body + 'UserName=first, '], hold)
isemon.ise_parse_lines([head % 0 + body], hold)
hold = {}
isemon.ise_parse_lines([head % 0 + body + 'UserName=twice, '] * 2, hold)
ok('the same part twice is only the same part', [len(v['parts']) for v in hold.values()], [1])
hold = {}
isemon.ise_parse_lines([head % 0 + body + 'UserName=first, '], hold)
isemon.ise_parse_lines([head % 0 + body], hold)
ok('a second, different part 0 under the same number starts another record',
   [len(v['parts']) for v in hold.values()], [1])

print('\nWindows: the address the client could not have written')
fields = isemon.win_fields(
    'An account failed to log on. Network Information: Workstation Name: X Source Network '
    'Address: 10.9.9.9 Source Network Address: 203.0.113.66 Source Port: 5000 ')
ok('the last address of the section is the real one', isemon.win_address(fields),
   '203.0.113.66')

print('\ntac_plus, FTD and FortiGate')
fields = {'Started': ['1791964800'], 'Stopped': ['1791972000'], 'Lasted': ['7200']}
ok('a session’s end is filed when it ended', isemon.tacplus_when('', fields)[0],
   1791972000.0)
ok('the firewall’s own stamp beats a relay’s ISO one',
   isemon._ftd_when('2026-10-14T10:05:00+02:00 relay1 Oct 14 2026 09:58:00 fw1 :')
   < isemon._ftd_when('2026-10-14T10:05:00+02:00 relay1 :'), True)
ok('an RFC 5424 line is from its host, not from `-`',
   isemon.ftd_host('<166>1 2026-10-14T10:00:00Z fw1 - - - '), 'fw1')
said = isemon.fg_fields('Oct  1 07:56:02 fgt.example.cz logver=700 devname="FG-1" '
                        'vd="root" date=2026-10-01 time=07:56:02 type=traffic')
ok('FortiGate pairs before `date=` are read', (said.get('devname'), said.get('_host')),
   ('FG-1', 'fgt.example.cz'))

print('\nThe upkeep')
ok('a stride that cannot be found is tried again later, not taken whole',
   "'later' % (table, str(e).split(chr(10))[0][:120]), 'debug')\n                break" in source,
   True)
ok('a day that could not be frozen is tried again, not written down as done',
   "self._settle_again_at = time.time() + 3600" in source, True)
ok('room is made for the night’s dump before it is made',
   'self._room_for_a_dump(keep)\n                where = self.store.dump(' in source, True)
ok('a copy to go back to is the engine’s dump on a big server',
   ("safety = self.safety_copy('before-restore')" in source,
    "where = self.store.safety_copy('before-erasing')" in source), (True, True))
ok('an index over a split table left part-built is finished, not dropped',
   ("AND c.relkind <> 'I' " in source, 'def unfinished_split_indexes(self, db):' in source),
   (True, True))
ok('the days missed while stopped are made', 'SPLIT_GAP_MOST = 31' in source, True)

if store.dialect.name == 'postgres':
    print('\nPostgreSQL: the days split')
    store, daemon = fresh()
    store.split_all(now=time.time() - 10 * 86400)
    apart = store.split_conn()
    try:
        have = store.split_children(apart, 'fw_events')
        gap_day = store.split_day_name('fw_events', time.time() - 3 * 86400)
        if gap_day in have:
            apart.execute('DROP TABLE %s' % gap_day)
        store._split_ensured = 0
        store.split_ensure(force=True)
        ok('a day missing in the middle is made again',
           gap_day in store.split_children(apart, 'fw_events'), True)
    finally:
        apart.close()

for one in FOLDERS:
    shutil.rmtree(one, ignore_errors=True)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
