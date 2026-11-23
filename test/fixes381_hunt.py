#!/usr/bin/env python3
"""1.10.381: bug hunt, round 10 of 10 - every change of rounds 1 to 9 read
again, and what any of them broke put back as it was.

    ./test/fixes381_hunt.py
"""
import gzip
import shutil
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


folder = Path(tempfile.mkdtemp(prefix='isemon-381-'))
for k, v in dict(STATE_DIR=folder, DB_FILE=folder / 'c.db', BACKUP_DIR=folder / 'b',
                 DUMP_DIR=folder / 'd', RUN_DIR=folder, LOG_DIR=folder,
                 CONFIG_FILE=folder / 'config.json', _LOG_PATH=folder / 'c.log',
                 TOKEN_FILE=folder / 'tok').items():
    setattr(isemon, k, v)
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0, 'otp': 1, 'tacplus': 1})

print('The log reader')


def plain(lines, hold=None, now=None):
    return [x.rstrip('\n') for x in lines if x.strip()]


def numbered(a, b):
    return ''.join('L%06d %s\n' % (i, 'x' * 40) for i in range(a, b))


p = str(folder / 'x.log')
open(p, 'w').write(numbered(0, 100))
tail = isemon.LogTail(p, parser=plain)
tail.read()
open(p, 'a').write(numbered(100, 110))
shutil.copyfile(p, p + '.1')
good = gzip.compress(numbered(0, 500).encode())
open(p + '.2.gz', 'wb').write(good[:20] + bytes(b ^ 0x5a for b in good[20:-8]) + good[-8:])
open(p, 'w').close()
open(p, 'a').write(numbered(200, 203))
try:
    got = tail.read() + tail.read()
except Exception as e:                                # noqa: BLE001
    got = ['raised %s' % type(e).__name__]
ok('a broken .gz beside a log is never in the way of reading it',
   (len(got), got[:1] == ['L000100 ' + 'x' * 40]), (13, True))

print('tac_plus')
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)
base = int(time.time()) - 3600
lines = []
for i, w in enumerate(['login', 'authen', 'author']):
    st = time.strftime('%b %d %H:%M:%S', time.localtime(base + i * 900))
    lines.append("%s tacsrv tac_plus[2461]: %s query for 'u%s' tty1 from 10.0.0.9 accepted"
                 % (st, w, w))
daemon.read_records(lines, kind='tacplus')
ok('an authen sign-in is a sitting, as a login one is', sorted(
    r['username'] for r in store.db.execute("SELECT username FROM passed WHERE kind = 'tacplus'")),
   ['uauthen', 'ulogin'])

print('FreeRADIUS')
H = 'Mon Oct 20 10:00:00 2025 : Auth: '
rows = isemon.frad_parse_lines([
    H + '(30) Login incorrect (mschap: MS-CHAP2-Response is incorrect): '
        '[bob/<via Auth-Type = eap>] (from client ap port 0 via TLS tunnel)',
    H + '(31) Login incorrect: [carol/<via Auth-Type = eap>] (from client ap2 port 1 '
        'cli 11-22-33-44-55-66)',
    H + '(32) Login incorrect (eap_peap: The users session was previously rejected): '
        '[bob/<via Auth-Type = eap>] (from client ap port 1 cli AA-BB-CC-DD-EE-FF)'])
said = {r.user: r.fields.get('Inner said') for r in rows}
ok('the tunnel\'s inner reason is bob\'s, never carol\'s',
   (said.get('carol'), said.get('bob')), (None, ['mschap: MS-CHAP2-Response is incorrect']))

print('RouterOS')
got = [dict(r.facts) for r in isemon.ros_parse_lines([
    'Oct 17 10:00:00 gw l2tp,ppp,info,account bob logged in, 10.8.0.3 from 203.0.113.7',
    'Oct 18 10:00:00 gw l2tp,ppp,info,account bob logged in, 10.8.0.4 from 198.51.100.9',
    'Oct 18 10:30:00 gw l2tp,ppp,info,account bob logged out, 1800 1 2 3 4',
    'Oct 18 11:00:00 gw l2tp,ppp,info,account bob logged in, 10.8.0.5 from 192.0.2.1',
    'Oct 18 11:30:00 gw l2tp,ppp,info,account bob logged out, 1800 1 2 3 4'],
    hold={}, now=1760000000)]
ok('a logout the router never wrote moves no later one onto the session before',
   [r['srcip'] for r in got if r['action'] == 'tunnel-down'], ['198.51.100.9', '192.0.2.1'])

print('Commands kept')
for cmd, want in (('snmp-server host 10.0.0.1 traps', 'snmp-server host 10.0.0.1 traps'),
                  ('snmp-server host 10.0.0.1 vrf MGMT version 2c public',
                   'snmp-server host 10.0.0.1 vrf MGMT version 2c (hidden)')):
    ok('"%s"' % cmd, isemon.command_kept(cmd), want)

print('acme')
now = time.mktime((2026, 12, 31, 23, 0, 0, 0, 0, -1))
m = isemon.ACME_ENVELOPE.match('Jan  1 00:30:00 acme acme-certs[1]: level=info kind=c '
                               'node=a who=b msg=x')
ok('a node an hour and a half ahead at New Year: next year, not last',
   time.localtime(isemon.acme_when(m, now))[:3], (2027, 1, 1))

print('The Traffic search')
q = isemon.FwQuery('a - b')
ok('a dash between words is a word, as before', q.match({'msg': 'a - b dash'}), True)
ok('...and before a bracket it is NOT', isemon.FwQuery('-(dstport:22)').match({'dstport': 22}),
   False)
ok('port~44 is port = 44, as before', isemon.FwQuery('port~44').match({'dstport': 44}), True)

print('The command line')
src = (ROOT / 'isemon.py').read_text()
ok('--export through a link (or /dev/stdout) without the secrets, as before',
   "(os.O_NOFOLLOW if args.secrets else 0)" in src)
ok('an import with another api_port says nothing of a database it never named',
   "if any(k in FILE_ONLY for k in given['settings']):" in src)
ok('an address by hand with IPv6 DNS servers only is taken',
   "_net_list((want.get('ipv6') or {}).get('dns'))" in src)
ok('the indexes over LOWER() of a big file built behind the daemon, not at the start',
   'self.mend_lower_indexes(at_start=True)' in src)

print('The page')
page = (ROOT / 'web' / 'index.php').read_text()
ok('an alert band drawn again when what it says changes',
   'return [a.key, a.level, a.title, a.says];' in page)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
