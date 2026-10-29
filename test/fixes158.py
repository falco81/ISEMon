#!/usr/bin/env python3
"""What 1.10.158 found wrong, each made to happen and then checked.

- passwords saved with the settings were in the database as they were typed,
  so every backup and copy of it carried them;
- a domain account signing in rewrote a local account of the same name;
- the ban feed's user name and password could be guessed without end;
- the read-only guard on the directory let an extended operation through
  that only carried the StartTLS name somewhere inside it;
- an address that went on trying through its ban cost the square of its
  attempts, on the reader;
- a ban by hand took over what an old automatic one had been charged with;
- device commands kept the secret and hid the word before it;
- one firewall counter past 2^63 lost the whole lot of lines it came with;
- a line a few seconds out of order at the change of the clocks moved the
  rest of the hour by an hour;
- a source clock behind this one let an address try freely after its ban;
- NPS wrote one address several ways;
- the notes beside bans were kept for ever;
- retention never deleted a table whose oldest rows all shared one moment;
- oldest first never reached the oldest rows;
- a backslash or an underscore in a search box.

    ./test/fixes158.py
"""
import json
import sys
import tempfile
import time
from datetime import datetime
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


def fresh(**cfg):
    folder = tempfile.mkdtemp(prefix='isemon-158-')
    isemon.STATE_DIR = Path(folder)
    isemon.DB_FILE = Path(folder) / 'f.db'
    isemon.BACKUP_DIR = Path(folder) / 'b'
    isemon.DUMP_DIR = Path(folder) / 'd'
    isemon.RUN_DIR = Path(folder)
    isemon.LOG_DIR = Path(folder)
    isemon._LOG_PATH = Path(folder) / 'l.log'
    isemon.CONFIG.clear()
    isemon.CONFIG.update(isemon.DEFAULTS)
    isemon.CONFIG.update({'watch_devices': '', 'feeds_ban': 0, 'judge_max_age_h': 0,
                          'geo': 0, 'mikrotik1': 0, 'mikrotik2': 0})
    isemon.CONFIG.update(cfg)
    isemon.Storage._unsealable = set()
    store = isemon.Storage(isemon.DB_FILE)
    daemon = isemon.Daemon(store)
    daemon._spare_from = None
    daemon.feed_wanted = lambda: []
    return store, daemon


def fail(store, ip, at, user='u', key=None):
    return store.add_failed({'session': key or 's/%s/%s/%s' % (ip, at, user), 'ts': at,
                             'ip': ip, 'username': user, 'device': 'FTD-VPN',
                             'server': 'ise2', 'detail': '{}'})


class Said(object):
    """A record as the reader hands it on: its moment and its name."""
    def __init__(self, ts, user):
        self.ts = ts
        self.user = user


print('\nPasswords kept with the settings')
store, daemon = fresh()
with store.db_write() as db:
    db.execute("INSERT INTO settings (key, value, at, by) VALUES ('directory_password', ?, 0, "
               "'old')", (json.dumps('Plain-Old-1'),))
daemon = isemon.Daemon(store)
raw = {r['key']: r['value'] for r in store.db.execute('SELECT key, value FROM settings')}
ok('one saved before is sealed the first time the daemon starts',
   'Plain-Old-1' in raw['directory_password'], False)
ok('...and still opens to what was typed', store.settings_saved()['directory_password'],
   'Plain-Old-1')
store.settings_write({'mikrotik_password': 'Žluťoučký kůň 9', 'block_tries': 7})
raw = {r['key']: r['value'] for r in store.db.execute('SELECT key, value FROM settings')}
ok('one saved now is never in the table as typed',
   ('kůň' in raw['mikrotik_password'], raw['block_tries']), (False, '7'))
ok('...and comes back as typed', store.settings_saved()['mikrotik_password'],
   'Žluťoučký kůň 9')
(Path(isemon.STATE_DIR) / 'settings.key').write_text('00' * 32 + '\n')
isemon.Storage._unsealable = set()
ok('a database brought from another machine opens without them, the rest intact',
   store.settings_saved(), {'block_tries': 7})
key = Path(isemon.STATE_DIR) / 'settings.key'
key.write_text('not a key\n')
isemon.Storage._unsealable = set()
store.settings_write({'banfeed_password': 'Feed-Pass-1234'})
ok('a key file that cannot be read is never replaced', key.read_text(), 'not a key\n')

print('\nA domain account and a local one of the same name')
store, daemon = fresh()
daemon.add_user('admin', 'Local-Passw0rd!', role='fulladmin')
daemon.directory_on = lambda: True
daemon.directory_sign_in = lambda name, password: {'name': name, 'role': 'readonly',
                                                   'dn': 'CN=admin,DC=example,DC=org'}
try:
    daemon.login('admin', 'whatever-the-domain-said', ip='192.0.2.10')
    ok('the domain\'s password is not a way into the local account', 'in', 'refused')
except isemon.Refused:
    ok('the domain\'s password is not a way into the local account', True)
got = daemon.login('admin', 'Local-Passw0rd!', ip='192.0.2.11')
kept = store.user('admin')
ok('...the local password is, as the local account',
   (got['role'], daemon.who(got['token'])['role'] if hasattr(daemon, 'who') else 'fulladmin'),
   ('fulladmin', 'fulladmin'))
daemon.directory_sign_in = lambda name, password: (_ for _ in ()).throw(
    isemon.LdapError('the directory refused it'))
got = daemon.login('admin', 'Local-Passw0rd!', ip='192.0.2.12')
ok('...and so is it when the domain account of that name has another password',
   got['role'], 'fulladmin')
ok('...and the local account is left exactly as it was',
   (kept['role'], int(kept.get('from_dir') or 0)), ('fulladmin', 0))

print('\nThe ban feed by user name and password')
store, daemon = fresh(banfeed=1, banfeed_auth='basic', banfeed_user='fw',
                      banfeed_password='Correct-Horse-99', login_tries=5)
codes = [daemon.banfeed_serve('', client='198.51.100.9', user='fw', password='wrong%d' % i)[0]
         for i in range(8)]
ok('wrong guesses are stopped after the sign-in\'s allowance', codes[-1], 429)
ok('...even with the right one, until the wait is over',
   daemon.banfeed_serve('', client='198.51.100.9', user='fw',
                        password='Correct-Horse-99')[0], 429)
ok('...and another address is not held for it',
   daemon.banfeed_serve('', client='198.51.100.10', user='fw',
                        password='Correct-Horse-99')[0], 200)

print('\nThe directory is only ever read')
ldap = isemon.Ldap.__new__(isemon.Ldap)
ldap.next_id = 1
sent = []
ldap.sock = type('S', (), {'sendall': lambda self, b: sent.append(b)})()
smuggled = isemon._ber(0x77, isemon._ber_str('1.3.6.1.4.1.4203.1.11.1', tag=0x80)
                       + isemon._ber_str(isemon._ber_str(isemon.Ldap.START_TLS_OID), tag=0x81))
try:
    ldap._send(smuggled)
    ok('a password change carrying the StartTLS name inside it is refused', 'sent', 'refused')
except isemon.LdapError:
    ok('a password change carrying the StartTLS name inside it is refused', not sent)
ldap._send(isemon._ber(0x77, isemon._ber_str(isemon.Ldap.START_TLS_OID, tag=0x80)))
ok('...and StartTLS itself still goes', len(sent), 1)

print('\nAn address that goes on trying through its ban')
store, daemon = fresh(block_tries=5, block_window_min=10, block_lots=25, block_bogus_tries=1,
                      block_ladder='1440')
ip = '203.0.113.88'
t0 = time.time() - 3600
for k in range(5):
    fail(store, ip, t0 + k, key='e%d' % k)
daemon.judge_refusal(ip, isemon._AtTime(t0 + 4), ['FTD-VPN'])
pulled = []
orig = store.failed_recent
store.failed_recent = lambda *a, **kw: pulled.append(1) or orig(*a, **kw)
began = time.time()
for k in range(600):
    ts = t0 + 10 + k * 0.1
    fail(store, ip, ts, user='realuser', key='h%d' % k)
    daemon.judge_refusal(ip, Said(ts, 'realuser'), ['FTD-VPN'])
store.failed_recent = orig
ok('six hundred attempts through a ban are out for good at the burst',
   store.blocked_one(ip)['until'], None)
ok('...and weighing them fetched rows only when there was something to do',
   len(pulled) < 20, True)
store, daemon = fresh(block_tries=5, block_window_min=10, block_bogus_tries=1,
                      block_bogus_names='INVALID')
for k in range(5):
    fail(store, ip, t0 + k, key='e%d' % k)
daemon.judge_refusal(ip, isemon._AtTime(t0 + 4), ['FTD-VPN'])
fail(store, ip, t0 + 20, user='INVALID', key='bogus')
daemon.judge_refusal(ip, Said(t0 + 20, 'INVALID'), ['FTD-VPN'])
ok('...and a name that never existed, offered through the ban, still puts it out for good',
   store.blocked_one(ip)['until'], None)

print('\nA ban by hand after an old automatic one')
store, daemon = fresh(block_tries=5, block_window_min=10, block_lots=25, block_bogus_tries=0)
ip = '203.0.113.50'
now = time.time()
for k in range(6):
    fail(store, ip, now - 86400 + k, key='y%d' % k)
daemon.maybe_block(ip, isemon._AtTime(now - 86400 + 5))
store.unblock(ip, how='ran out')
for k in range(30):
    fail(store, ip, now - 80000 + k * 60, key='m%d' % k)
daemon.ban(ip, minutes=60, why='by hand', by='admin')
until = store.blocked_one(ip)['until']
fail(store, ip, time.time(), key='one-more')
daemon.judge_refusal(ip, Said(time.time(), 'u'), ['FTD-VPN'])
ok('one attempt after it does not make it for good', store.blocked_one(ip)['until'], until)

print('\nSecrets typed on a switch')
for typed, kept in (('wpa-psk ascii 0 WifiPass123', 'wpa-psk ascii 0 (hidden)'),
                    ('ntp authentication-key 1 md5 NtpSecret7',
                     'ntp authentication-key 1 md5 (hidden)'),
                    ('snmp-server user mon grp v3 auth sha AuthPass1 priv aes 128 PrivPass1',
                     'snmp-server user mon grp v3 auth sha (hidden) priv aes 128 (hidden)'),
                    ('username admin privilege 15 password 0 Pass',
                     'username admin privilege 15 password 0 (hidden)'),
                    ('snmp-server community public RO', 'snmp-server community (hidden) RO'),
                    ('snmp-server community 4711 RO', 'snmp-server community (hidden) RO'),
                    ('crypto isakmp key 123456 address 192.0.2.1',
                     'crypto isakmp key (hidden) address 192.0.2.1'),
                    ('username bob password 1234 privilege 15',
                     'username bob password (hidden) privilege 15'),
                    ('password 7 0822455D0A16', 'password 7 (hidden)'),
                    ('pre-shared-key 0 type 7 abc', 'pre-shared-key 0 type 7 (hidden)'),
                    ('username x secret 10 $6$abc', 'username x secret 10 (hidden)'),
                    ('snmp-server community 47 RO', 'snmp-server community (hidden) RO'),
                    ('key chain KC', 'key chain KC'),
                    ('crypto key generate rsa modulus 2048',
                     'crypto key generate rsa modulus 2048'),
                    ('snmp-server group G v3 auth read V', 'snmp-server group G v3 auth read V')):
    ok('%s' % kept, isemon.command_kept(typed), kept)

print('\nA firewall counter past what a column holds')
store, daemon = fresh()
lines = []
for k in range(6):
    lines.append({'ident': 'big%d' % k, 'ts': time.time() - 60 + k, 'type': 'traffic',
                  'sub': 'forward', 'action': 'close', 'verdict': 'allow',
                  'srcip': '192.0.2.%d' % (k + 1), 'dstip': '198.51.100.1',
                  'sent': '18446744073709551615' if k == 3 else '1000', 'rcvd': 10,
                  'fields': {}})
lines = [dict(f, sent=isemon.fg_number(f['sent'])) for f in lines]
store._note_fw_events(lines)
ok('the other lines of its lot are written', store.db.execute(
    'SELECT COUNT(*) AS n FROM fw_events').fetchone()['n'], 6)
ok('...and it is kept as the most a line can carry', store.db.execute(
    "SELECT sent FROM fw_events WHERE ident='big3'").fetchone()['sent'],
   isemon.FW_COUNTER_MOST)

print('\nThe night the clocks go back')
try:
    from zoneinfo import ZoneInfo
    zone = ZoneInfo('Europe/Prague')

    def read(seq):
        last, out = {}, []
        for one in seq:
            h, m, s = map(int, one.split(':'))
            ts = isemon.wall_clock_ts(datetime(2026, 10, 25, h, m, s, tzinfo=zone), last)
            out.append(datetime.fromtimestamp(ts, zone).strftime('%H:%M:%S %Z'))
        return out
    ok('a line two seconds out of order moves nothing',
       read(['02:10:00', '02:09:58', '02:10:01', '02:20:00']),
       ['02:10:00 CEST', '02:09:58 CEST', '02:10:01 CEST', '02:20:00 CEST'])
    ok('...and the hour that really happens twice is still read as twice',
       read(['01:59:00', '02:59:59', '02:00:01', '02:30:00', '03:00:01']),
       ['01:59:00 CEST', '02:59:59 CEST', '02:00:01 CET', '02:30:00 CET', '03:00:01 CET'])
except ImportError:
    ok('zoneinfo is here to check the clocks with', False)

print('\nAn address read from a backlog, banned, served, let back in')
store, daemon = fresh(block_tries=5, block_window_min=60, block_bogus_tries=0,
                      judge_max_age_h=24)
ip = '203.0.113.66'
back = time.time() - 3000
for k in range(5):
    fail(store, ip, back + k, key='b%d' % k)
    daemon.judge_refusal(ip, isemon._AtTime(back + k), ['FTD-VPN'])
for k in range(4):
    fail(store, ip, time.time() - 60 + k, key='d%d' % k)
    daemon.judge_refusal(ip, isemon._AtTime(time.time() - 60 + k), ['FTD-VPN'])
with store.db_write() as db:
    db.execute('UPDATE blocked SET until=? WHERE ip=?', (time.time() - 1, ip))
store.sweep_expired()
fail(store, ip, time.time() + 1, key='after')
daemon.judge_refusal(ip, isemon._AtTime(time.time() + 1), ['FTD-VPN'])
ok('one attempt after its ban ran out does not ban it again', store.blocked_one(ip), None)

print('\nNPS and one address written several ways')
rec = isemon.NpsRecord.__new__(isemon.NpsRecord)
rec.door = 'nps-vpn'
rec.fields = {'Calling-Station-Id': ['2001:0DB8:0000:0000:0000:0000:0000:0007']}
ok('one spelling', rec.ip, '2001:db8::7')
rec.fields = {'Calling-Station-Id': ['0.0.0.0/0']}
ok('...and a range is nobody\'s address', rec.ip, '')

print('\nThe notes beside bans long over')
store, daemon = fresh(block_tries=3, block_window_min=10, block_bogus_tries=0)
now = time.time()
for k in range(20):
    one = '198.18.0.%d' % k
    for i in range(3):
        fail(store, one, now - 30 + i, key='%s/%d' % (one, i))
    daemon.maybe_block(one, isemon._AtTime(now))
with store.db_write() as db:
    db.execute('UPDATE blocked SET until=?', (now - 1,))
store.sweep_expired()
with store.db_write() as db:
    db.execute('UPDATE block_events SET ts=ts-10*86400')
daemon.ban('198.18.1.0/24', why='a range', by='admin')
store.set_meta('blocked_members_198.18.1.0/24', json.dumps([{'ip': '198.18.1.7'}]))
store.set_meta('blocked_proof_198.18.1.7', '[]')
ok('let go a week after the address was let back in',
   (store.tidy_ban_marks() > 0, store.db.execute(
       "SELECT COUNT(*) AS n FROM meta WHERE key LIKE 'blocked!_%' ESCAPE '!' "
       "AND key LIKE '%198.18.0.%'").fetchone()['n']), (True, 0))
ok('...but not those of an address folded into a range still banned',
   store.get_meta('blocked_proof_198.18.1.7'), '[]')

print('\nRetention over rows of one moment')
store, daemon = fresh()
with store.db_write() as db:
    for i in range(10):
        db.execute("INSERT INTO events (ts, kind, level, detail) VALUES (?, 'x', 'info', 'd')",
                   (100.0 if i < 5 else 200.0 + i,))
store.tidy_older('events', 1000.0, stride=3)
ok('everything older than the cut goes', store.db.execute(
    'SELECT COUNT(*) AS n FROM events').fetchone()['n'], 0)

print('\nOldest first, and searching')
store, daemon = fresh()
with store.db_write() as db:
    db.executemany('INSERT INTO passed (session, ts, ip, username, kind) VALUES (?,?,?,?,?)',
                   [('p%06d' % i, 1700000000.0 + i, '10.0.0.1', 'u%d' % i, 'vpn')
                    for i in range(isemon.SORT_WINDOW + 50)])
    db.executemany('INSERT INTO win_events (ident, ts, server, event, kind, account, said) '
                   'VALUES (?,?,?,?,?,?,?)',
                   [('w1', 1700000000, 'dc1', 4625, 'logon-failed', 'CORP\\jan_novak', 'x'),
                    ('w2', 1700000001, 'dc1', 4625, 'logon-failed', 'janXnovak', 'x')])
rows, _ = store.passed_rows(sort='ts', desc=False, limit=1, kind='all')
ok('oldest first starts at the oldest', rows[0]['ts'], 1700000000.0)
ok('a backslash is a backslash', [r['account'] for r in store.win_rows(text='corp\\jan')[0]],
   ['CORP\\jan_novak'])
ok('...and an underscore an underscore',
   [r['account'] for r in store.win_rows(text='jan_novak')[0]], ['CORP\\jan_novak'])

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
