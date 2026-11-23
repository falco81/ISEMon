#!/usr/bin/env python3
"""1.10.372: bug hunt, round 1 of 10 - the RADIUS readers, who may do what,
and the alerts. All names and addresses made up.

    ./test/fixes372_hunt.py
"""
import json
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
import isemon                                        # noqa: E402

PASS = FAIL = 0
PORT = 18972


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


print('FreeRADIUS and eduroam')
H = 'Sep 23 10:00:00 rad radiusd[1]: Auth: '
inner = H + ('(8) Login incorrect (mschap: MS-CHAP2-Response is incorrect): '
             '[bob/<via Auth-Type = eap>] (from client ap port 0 via TLS tunnel)')
outer = H + ('(8) Login incorrect (eap_peap: The users session was previously rejected): '
             '[anonymous@ex.cz/<via Auth-Type = eap>] (from client ap port 1 cli AA-BB-CC-DD-EE-FF)')
got = isemon.frad_parse_lines([inner, outer])
ok('the tunnel\'s inner refusal said on the outer one, by the request\'s number',
   [(r.user, r.fields.get('Inner said')) for r in got],
   [('anonymous@ex.cz', ['mschap: MS-CHAP2-Response is incorrect'])])
got = isemon.frad_parse_lines([inner.replace('(8)', '(30)'), outer.replace('(8)', '(31)')])
ok('...numbered on its own, just before the outer one, as FreeRADIUS does',
   [(r.user, r.fields.get('Inner said')) for r in got],
   [('anonymous@ex.cz', ['mschap: MS-CHAP2-Response is incorrect'])])
lines = [H + 'Invalid user: [bob/<via Auth-Type = pap>] (from client vpn port 0 cli 203.0.113.9)',
         H + 'Login incorrect: [alice/<via Auth-Type = pap>] (from client vpn port 0 cli 203.0.113.8)',
         H + 'Login incorrect: [bob/<via Auth-Type = pap>] (from client vpn port 0 cli 203.0.113.9)']
got = isemon.frad_parse_lines(lines)
ok('no request numbers: another\'s line between does not make one refusal two',
   sorted(r.user for r in got), ['alice', 'bob'])
ok('a name "host" with a slash in its password keeps none of the password',
   isemon.edu_account('host/hunter/2'), 'host')
ok('...a machine still a machine', isemon.edu_account('host/PC12.ex.int@ex.int/<via x>'),
   'host/PC12.ex.int@ex.int')

print('ISE')
ok('the domain out of the resolved DN, its commas escaped as ISE writes them',
   isemon.ise_realm({'AD-User-Resolved-DNs': ['CN=Jan Novak\\,OU=People\\,DC=corpnet\\,DC=loc']}),
   'corpnet.loc')

print('Who may do what')
folder = Path(tempfile.mkdtemp(prefix='isemon-372-'))
for k, v in dict(STATE_DIR=folder, DB_FILE=folder / 'c.db', BACKUP_DIR=folder / 'b',
                 DUMP_DIR=folder / 'd', RUN_DIR=folder, LOG_DIR=folder,
                 CONFIG_FILE=folder / 'config.json', _LOG_PATH=folder / 'c.log',
                 TOKEN_FILE=folder / 'tok').items():
    setattr(isemon, k, v)
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0, 'api_port': PORT, 'passkeys': 1,
                      'banfeed_user': 'fw-fetcher-7', 'banfeed_from': '10.20.30.40'})
store = isemon.Storage(isemon.DB_FILE)
d = isemon.Daemon(store)
d.add_user('boss', 'a-long-enough-password-1', 'fulladmin', by='test')
d.add_user('look', 'a-long-enough-password-2', 'readonly', by='test')
api = isemon.ApiServer(d, PORT)
api.start()
time.sleep(0.4)


def call(path, payload=None, session=''):
    req = urllib.request.Request('http://127.0.0.1:%d%s' % (PORT, path),
                                 data=json.dumps(payload).encode() if payload is not None
                                 else None, method='POST' if payload is not None else 'GET')
    req.add_header('X-Isemon-Token', isemon.API_TOKEN)
    req.add_header('X-Isemon-Session', session)
    if payload is not None:
        req.add_header('Content-Type', 'application/json')
    try:
        with urllib.request.urlopen(req, timeout=30) as a:
            return a.status, json.loads(a.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or '{}')


try:
    boss = store.new_session('boss', 'fulladmin', '127.0.0.1', 'test', '')
    look = store.new_session('look', 'readonly', '127.0.0.1', 'test', '')
    store.put_passkeys([{'id': 'k1', 'user': 'boss', 'name': 'iPad', 'pem': 'x', 'host': 'h'}])
    st, _b = call('/api/auth/passkeys', {'do': 'reset', 'name': 'boss'}, boss)
    ok('one\'s own Face ID not set up again without Face ID just before', st, 428)
    ok('...the passkey still there', len(store.passkeys()), 1)
    st, _b = call('/api/users', {'password_for': 'boss', 'password': 'another-long-pass-9'}, boss)
    ok('one\'s own password not set as anybody\'s (it takes the old one, under My account)',
       st, 409)
    st, body = call('/api/settings', session=look)
    vals = {one.get('key'): one.get('value') for one in body.get('settings', [])} \
        if isinstance(body.get('settings'), list) else {}
    ok('a viewer sees neither the ban list\'s account nor who fetches it',
       (vals.get('banfeed_user'), vals.get('banfeed_from')), ('', ''))
finally:
    api.httpd.shutdown()
    api.httpd.server_close()

print('The alerts')
store.add_event('control', 'something failed', 'bad')
ok('an event that failed is an error', store.db.execute(
    "SELECT level FROM events WHERE detail = 'something failed'").fetchone()['level'], 'error')
page = (ROOT / 'web' / 'index.php').read_text()
ok('"not now" outlasts the numbers changing in an alert',
   ".replace(/[0-9][0-9.,\\s]*/g, '#'), h = 0;" in page)
ok('a SELinux look with no answer keeps what was known',
   "if err and not data and isinstance(now.get('data'), dict):" in
   (ROOT / 'isemon.py').read_text())

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
