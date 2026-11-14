#!/usr/bin/env python3
"""1.10.340: signing in with Windows (Kerberos), as otp 1.0.274 does it. A
realm of its own is made here (MIT krb5-kdc, test/kdc_krb5.sh): tickets are
real, made by the system's GSS-API as a browser on Linux makes them, and
checked by isemon against a keytab put in on the pages. The directory is
made up at its edge (the search for the person, their groups).

Without krb5-kdc on the machine, the realm cannot be made: the parts that
need no ticket run, the rest is said to be skipped.

    ./test/fixes340_kerberos.py
"""
import base64
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
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


folder = Path(tempfile.mkdtemp(prefix='isemon-340-'))
isemon.STATE_DIR = folder
isemon.DB_FILE = folder / 'c.db'
isemon.BACKUP_DIR = folder / 'backups'
isemon.DUMP_DIR = folder / 'dumps'
isemon.RUN_DIR = folder
isemon.LOG_DIR = folder
isemon.CONFIG_FILE = folder / 'config.json'
isemon._LOG_PATH = folder / 'c.log'
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0, 'directory': 1,
                      'directory_host': 'dc.corpnet.loc', 'directory_base': 'DC=corpnet,DC=loc',
                      'directory_admin_group': 'ISEMON_Admins',
                      'directory_readonly_group': 'ISEMON_Viewers'})
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)
source = (HERE.parent / 'isemon.py').read_text()
page = (HERE.parent / 'web' / 'index.php').read_text()

print('off by default, and nothing of it offered')
ok('off', (isemon.DEFAULTS['kerberos'], isemon.DEFAULTS['password_off']), (0, 0))
ok('the sign-in page is told off', daemon.kerberos_health(),
   {'on': False, 'auto': False, 'only': False, 'cert': False, 'cert_port': 0, 'cert_auto': False})
ok('the realm from the directory\'s base DN', daemon.kerberos_realm(), 'CORPNET.LOC')
isemon.CONFIG['kerberos_realm'] = 'corp.example'
ok('...or as set, in capitals', daemon.kerberos_realm(), 'CORP.EXAMPLE')
isemon.CONFIG['kerberos_realm'] = ''

print('NTLM never, and nothing that is not a ticket')
ntlm = b'NTLMSSP\x00\x01\x00\x00\x00' + b'\x00' * 20
for what, tok in (('NTLM bare', ntlm), ('NTLM inside SPNEGO', b'\x60\x30\xa0' + ntlm),
                  ('nothing', b''), ('far too big', b'x' * 70000)):
    try:
        isemon.gss_accept(tok)
        ok(what + ': refused', False)
    except isemon.KrbError as e:
        ok('%s: refused (%s)' % (what, str(e)[:50]), True)
for bad in ('HTTP/x.corp@CORP', 'a@b@c', 'nobody', 'CORP\\x@CORP'):
    try:
        isemon.krb_split(bad)
        ok('%s refused as a person' % bad, False)
    except isemon.KrbError:
        ok('%s refused as a person' % bad, True)
ok('a person', isemon.krb_split('falco@corpnet.loc'), ('falco', 'CORPNET.LOC'))
ok('FILETIME read', (isemon.krb_filetime('0'), isemon.krb_filetime(str(0x7FFFFFFFFFFFFFFF)),
                     round(isemon.krb_filetime('133000000000000000'))), (0, 0, 1655526400))

KDC_THERE = all(shutil.which(x) for x in ('krb5kdc', 'kadmin.local', 'kinit', 'kdb5_util'))
if not KDC_THERE or isemon.gss_lib() is None:
    print('\n(skipped: no krb5-kdc or libgssapi_krb5 on this machine - the tickets need them)')
    print('\n%d passed, %d failed' % (PASS, FAIL))
    sys.exit(1 if FAIL else 0)

kdc = folder / 'kdc'
port = 20000 + random.randint(0, 9000)
got = subprocess.run(['bash', str(HERE / 'kdc_krb5.sh'), str(kdc), str(port)],
                     capture_output=True, text=True, timeout=120)
if got.returncode:
    print(got.stdout, got.stderr)
    raise SystemExit('the test realm could not be made')

TOK = r'''
import base64, ctypes, ctypes.util, os, sys
class Buf(ctypes.Structure):
    _fields_ = [('length', ctypes.c_size_t), ('value', ctypes.c_void_p)]
class Oid(ctypes.Structure):
    _fields_ = [('length', ctypes.c_uint32), ('elements', ctypes.c_void_p)]
def oid(raw):
    b = ctypes.create_string_buffer(raw, len(raw)); o = Oid(len(raw), ctypes.cast(b, ctypes.c_void_p)); o._k = b; return o
kdc, person, host, mech = sys.argv[1:5]
os.environ['KRB5_CONFIG'] = kdc + '/krb5.conf'
os.environ['KRB5CCNAME'] = 'FILE:%s/%s.cc' % (kdc, person)
lib = ctypes.CDLL(ctypes.util.find_library('gssapi_krb5') or 'libgssapi_krb5.so.2')
P, U, V = ctypes.POINTER, ctypes.c_uint32, ctypes.c_void_p
lib.gss_import_name.argtypes = [P(U), P(Buf), P(Oid), P(V)]
lib.gss_init_sec_context.argtypes = [P(U), V, P(V), V, P(Oid), U, U, V, P(Buf), P(P(Oid)), P(Buf), P(U), P(U)]
m = U(); nb = ('HTTP@' + host).encode(); nbuf = Buf(len(nb), ctypes.cast(ctypes.c_char_p(nb), V)); name = V()
if lib.gss_import_name(ctypes.byref(m), ctypes.byref(nbuf), ctypes.byref(oid(bytes.fromhex('2a864886f71201020104'))), ctypes.byref(name)):
    raise SystemExit('import_name')
mo = oid(bytes.fromhex('2b0601050502' if mech == 'spnego' else '2a864886f712010202'))
ctx, out = V(), Buf()
r = lib.gss_init_sec_context(ctypes.byref(m), None, ctypes.byref(ctx), name, ctypes.byref(mo), 0, 0, None, None, None, ctypes.byref(out), None, None)
if r not in (0, 1):
    raise SystemExit('init_sec_context %#x/%d' % (r, m.value))
print(base64.b64encode(ctypes.string_at(out.value, out.length)).decode())
'''


def ticket(person, host='isemon.corpnet.loc', mech='spnego'):
    r = subprocess.run([sys.executable, '-c', TOK, str(kdc), person, host, mech],
                       capture_output=True, text=True, timeout=60)
    if r.returncode:
        raise SystemExit('no ticket for %s: %s' % (person, r.stderr.strip()[-200:]))
    return r.stdout.strip()


DN = 'OU=People,DC=corpnet,DC=loc'
PEOPLE = {
    'falco': {'groups': {'isemon_admins'}},
    'pkolar': {'groups': {'isemon_viewers'}},
    'nogroups': {'groups': set()},
    'gone': {'groups': {'isemon_admins'}, 'uac': '514'},
    'edvorak': {'groups': {'isemon_admins'}, 'lockout': '133000000000000000'},
    'jnovak': {'groups': {'isemon_admins'}, 'expires': '130000000000000000'},
    'admin': {'groups': {'isemon_admins'}},
    'twice': {'groups': {'isemon_admins'}, 'many': True},
}


class Link(object):
    def close(self):
        pass


def find(link, user):
    p = PEOPLE.get(user.lower())
    if not p:
        return []
    one = {'dn': 'CN=%s,%s' % (user, DN), 'attrs': {
        'distinguishedName': ['CN=%s,%s' % (user, DN)], 'sAMAccountName': [user],
        'userPrincipalName': ['%s@corpnet.cz' % user], 'displayName': [user.title()],
        'userAccountControl': [p.get('uac', '512')], 'lockoutTime': [p.get('lockout', '0')],
        'accountExpires': [p.get('expires', '0')], 'memberOf': []}, '_groups': p['groups']}
    return [one, dict(one, dn='CN=other')] if p.get('many') else [one]


daemon.directory_reader = lambda which='directory', timeout=None: Link()
daemon.kerberos_find = find
daemon.directory_groups = lambda link, entry: set(entry.get('_groups') or ())

print('the keytab, put in on the pages')
isemon.CONFIG['kerberos'] = 1
raw = (kdc / 'http.keytab').read_bytes()
for bad, why in ((b'nothing', 'not a keytab'), ((kdc / 'falco.keytab').read_bytes(),
                                                  'no HTTP/ name')):
    try:
        daemon.kerberos_put(bad, 'boss')
        ok('refused: ' + why, False)
    except ValueError as e:
        ok('refused: %s (%s)' % (why, str(e)[:40]), why in str(e))
entries = daemon.kerberos_put(raw, 'boss')
ok('its names and keys read, never a key', sorted({e['principal'] for e in entries}),
   ['HTTP/isemon.corpnet.loc@CORPNET.LOC', 'HTTP/isemon2.corpnet.loc@CORPNET.LOC'])
ok('...no key in what is shown', 'key' not in json.dumps(daemon.kerberos_view(True)['keytab'])
   .replace('"kvno"', '').replace('keytab', ''), True)
ok('kept sealed', 'sealed' in store.get_meta('kerberos_keytab') and
   base64.b64encode(raw).decode() not in store.get_meta('kerberos_keytab'), True)
ok('on now', daemon.kerberos_on(), True)

print('signing in with a ticket')
got = daemon.kerberos_login(ticket('falco'), ip='10.1.1.5', agent='test')
ok('falco: full admin, out of the directory', (got['name'], got['role'], got['from_dir'],
                                                got['how']), ('falco', 'fulladmin', True,
                                                              'kerberos'))
ok('...a session made', store.user('falco')['from_dir'], 1)
ok('...and marked as made by Kerberos', daemon.kerberos_session(got['token']), True)
ok('the keytab written 0600', oct((folder / 'kerberos' / 'http.keytab').stat().st_mode & 0o777),
   '0o600')
got = daemon.kerberos_login(ticket('pkolar', 'isemon2.corpnet.loc'), ip='10.1.1.6')
ok('pkolar by the other name of the same keytab: read only', (got['name'], got['role']),
   ('pkolar', 'readonly'))
got = daemon.kerberos_login(ticket('falco', mech='krb5'), ip='10.1.1.5')
ok('bare Kerberos (no SPNEGO) too', got['name'], 'falco')
daemon.add_user('admin', 'local-password-1', 'fulladmin')
for person, host, why in (('nogroups', None, 'none of the groups'),
                          ('gone', None, 'switched off'), ('edvorak', None, 'locked out'),
                          ('jnovak', None, 'expired'), ('ghost', None, 'not in the directory'),
                          ('admin', None, 'an account of this machine'),
                          ('twice', None, 'more than one entry'),
                          ('falco', 'other.corpnet.loc', 'not taken')):
    try:
        daemon.kerberos_login(ticket(person, host or 'isemon.corpnet.loc'), ip='10.1.2.%d'
                              % random.randint(1, 250))
        ok('%s refused: %s' % (person, why), False)
    except isemon.KrbError as e:
        ok('%s refused: %s' % (person, why), why in str(e) or str(e))
        if why not in str(e):
            print('          said: %s' % e)
tok = ticket('falco')
daemon.kerberos_login(tok, ip='10.1.3.1')
try:
    daemon.kerberos_login(tok, ip='10.1.3.1')
    ok('the same ticket again: refused', False)
except isemon.KrbError as e:
    ok('the same ticket again: refused (%s)' % str(e)[:60], True)
isemon.CONFIG['kerberos_realm'] = 'OTHER.EXAMPLE'
try:
    daemon.kerberos_login(ticket('falco'), ip='10.1.3.2')
    ok('another realm than set: refused', False)
except isemon.KrbError as e:
    ok('another realm than set: refused', 'only OTHER.EXAMPLE signs in' in str(e))
isemon.CONFIG['kerberos_realm'] = ''
ev = store.db.execute("SELECT level, detail FROM events WHERE detail LIKE '%with Windows%' "
                      "AND level='warn' ORDER BY id DESC").fetchone()
ok('a refusal is in the events, a warning', ev and ev['level'], 'warn')

print('the second step after it, every time')
isemon.CONFIG['passkeys'] = 1
got = daemon.kerberos_login(ticket('falco'), ip='10.1.4.1')
ok('Face ID owed after a Windows sign-in', got['second'], 'enrol')
isemon.CONFIG['passkeys'] = 0

print('try my browser\'s ticket: nobody signed in')
before = len(store.sessions())
said = daemon.kerberos_check(ticket('pkolar'))
ok('who it would sign in, and as what', (said['principal'], said['name'], said['role']),
   ('pkolar@CORPNET.LOC', 'pkolar', 'readonly'))
ok('...no session made', len(store.sessions()), before)

print('only Windows')
isemon.CONFIG['password_off'] = 1
ok('in effect', daemon.password_off(), True)
for who, pw in (('admin', 'local-password-1'), ('falco', 'x')):
    try:
        daemon.login(who, pw, ip='10.1.5.1')
        ok('%s with a password: refused' % who, False)
    except isemon.Refused as e:
        ok('%s with a password: refused' % who, 'no password signs in here' in str(e))
try:
    daemon.passwords_refused()
    ok('passwords_refused says so', False)
except ValueError:
    ok('passwords_refused says so', True)
isemon.CONFIG['kerberos'] = 0
ok('Kerberos off brings passwords back', (daemon.password_off(),
                                          daemon.login('admin', 'local-password-1',
                                                       ip='10.1.5.2')['name']), (False, 'admin'))
isemon.CONFIG['kerberos'] = 1
isemon.CONFIG['password_off'] = 0
ok('switched on only from a Windows sign-in', 'daemon.kerberos_session(self.headers.get('
   "'X-Isemon-Session') or '')" in source)
ok('the PHP answers a refusal with 403, never a second 401',
   "http_response_code($status === 401 ? 403" in page)

print('through the page: nginx and PHP as a browser meets them (curl --negotiate)')
if shutil.which('php') and shutil.which('curl'):
    import time
    import urllib.request
    PORT = 30000 + random.randint(0, 2000)
    WEB = PORT + 3000
    isemon.TOKEN_FILE = folder / 'api-token'
    api = isemon.ApiServer(daemon, PORT)
    api.start()
    time.sleep(0.4)
    isemon.TOKEN_FILE.write_text(isemon.API_TOKEN + '\n')
    web = folder / 'web'
    shutil.copytree(str(HERE.parent / 'web'), str(web))
    lines = []
    for line in (web / 'isemon-api.php').read_text().split('\n'):
        if line.startswith('const ISEMON_PORT '):
            line = 'const ISEMON_PORT    = %d;' % PORT
        elif line.startswith('const ISEMON_TOKEN '):
            line = "const ISEMON_TOKEN   = '%s';" % isemon.TOKEN_FILE
        lines.append(line)
    (web / 'isemon-api.php').write_text('\n'.join(lines))
    php = subprocess.Popen(['php', '-S', '127.0.0.1:%d' % WEB, '-t', str(web)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.0)
    base = 'http://isemon.corpnet.loc:%d/index.php?api=kerberos-login' % WEB

    def curl(person=None, extra=()):
        env = dict(os.environ, KRB5_CONFIG=str(kdc / 'krb5.conf'))
        for k in ('http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY'):
            env.pop(k, None)
        args = ['curl', '-s', '-i', '--noproxy', '*', '-X', 'POST', '-H',
                'Content-Type: application/json', '-d', '{}',
                '--resolve', 'isemon.corpnet.loc:%d:127.0.0.1' % WEB] + list(extra)
        if person:
            env['KRB5CCNAME'] = 'FILE:%s/%s.cc' % (kdc, person)
            args += ['--negotiate', '-u', ':']
        r = subprocess.run(args + [base], capture_output=True, text=True, timeout=60, env=env)
        if os.environ.get('KRB_DEBUG'):
            print(repr(r.stdout[:1500]), r.stderr[:300])
        text = r.stdout.replace('\r\n', '\n')
        heads, _, body = text.rpartition('\n\n')
        codes = [int(x) for x in re.findall(r'(?m)^HTTP/1\.\d (\d+)', r.stdout)]
        try:
            data = json.loads(body or '{}')
        except ValueError:
            data = {}
        return codes, heads, data
    import re
    try:
        isemon.CONFIG['kerberos'] = 1
        daemon.kerberos_put(raw, 'boss')
        codes, heads, data = curl()
        ok('no ticket: 401 and WWW-Authenticate: Negotiate',
           (codes[-1], 'WWW-Authenticate: Negotiate' in heads), (401, True))
        codes, heads, data = curl('falco')
        ok('falco: the ticket, then 200', codes[-1], 200)
        ok('...signed in, the session in a cookie and not in the page',
           (data.get('name'), data.get('role'), 'token' in data,
            'Set-Cookie:' in heads or 'set-cookie:' in heads.lower()),
           ('falco', 'fulladmin', False, True))
        codes, heads, data = curl('nogroups')
        ok('known, in no group: 403 - never a second 401', (codes[-1], codes.count(401) <= 1),
           (403, True))
        ok('...and said why', 'none of the groups' in (data.get('error') or ''), True)
        codes, heads, data = curl(extra=['-H', 'Authorization: Negotiate ' + base64.b64encode(
            ntlm).decode()])
        ok('NTLM in the header: 403', codes, [403])
        codes, heads, data = curl(extra=['-H', 'Authorization: NTLM TlRMTVNTUAAB'])
        ok('Authorization: NTLM: 403', codes, [403])
        isemon.CONFIG['kerberos'] = 0
        codes, heads, data = curl('falco')
        ok('off: nothing of it (404)', codes[-1], 404)
        isemon.CONFIG['kerberos'] = 1
        r = urllib.request.urlopen(urllib.request.Request(
            'http://127.0.0.1:%d/index.php' % WEB), timeout=30)
        text = r.read().decode()
        ok('the sign-in page offers the button', 'id="krb-go"' in text and
           'Sign in with Windows' in text, True)
        isemon.CONFIG['password_off'] = 1
        text = urllib.request.urlopen('http://127.0.0.1:%d/index.php' % WEB, timeout=30).read() \
            .decode()
        ok('only Windows: the form hidden, the button the main one',
           ('id="signin-form" autocomplete="on" hidden' in text, 'data-only="1"' in text),
           (True, True))
        isemon.CONFIG['password_off'] = 0
    finally:
        php.terminate()
        api.stop() if hasattr(api, 'stop') else None
else:
    print('  (skipped: no php or curl)')

print('the keytab taken away')
daemon.kerberos_take_away('boss')
ok('off, and the file gone', (daemon.kerberos_on(),
                              (folder / 'kerberos' / 'http.keytab').exists()), (False, False))
try:
    os.kill(int((kdc / 'kdc.pid').read_text()), 15)
except (OSError, ValueError):
    pass
print('\n%d passed, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
