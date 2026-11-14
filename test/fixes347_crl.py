#!/usr/bin/env python3
"""1.10.347: the CRLs of the sign-in with a certificate, as acme 1.0.104 checks
and shows them. A test PKI (test/pki_crl.sh): a root, an issuing authority
naming the root's CRL, a base CRL and a delta CRL, an authority the root
revoked. Checked: what is fetched and from where (http only, never a
loopback, link-local or metadata address, no redirect, a size cap), the
delta, the authorities above, the ten-minute cache and the last good copy,
the card's rows, Fetch now and Clear (a full administrator only), the
events, what the person is told, and the command line.

    ./test/fixes347_crl.py
"""
import argparse
import http.server
import io
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from contextlib import redirect_stdout
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


folder = Path(tempfile.mkdtemp(prefix='isemon-347-'))
isemon.STATE_DIR = folder
isemon.DB_FILE = folder / 'c.db'
isemon.BACKUP_DIR = folder / 'backups'
isemon.DUMP_DIR = folder / 'dumps'
isemon.RUN_DIR = folder
isemon.LOG_DIR = folder
isemon.CONFIG_FILE = folder / 'config.json'
isemon._LOG_PATH = folder / 'c.log'
isemon.TOKEN_FILE = folder / 'api-token'
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0, 'directory': 1,
                      'directory_host': 'dc.corp.example', 'directory_base': 'DC=corp,DC=example',
                      'directory_admin_group': 'ISEMON_Admins'})
for k in ('http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY'):
    os.environ.pop(k, None)
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)

port = 23000 + random.randint(0, 3000)
pki = folder / 'pki'
got = subprocess.run(['bash', str(HERE / 'pki_crl.sh'), str(pki), str(port)],
                     capture_output=True, text=True, timeout=300)
if got.returncode:
    print(got.stdout, got.stderr)
    raise SystemExit('the test authority could not be made')
U = 'http://127.0.0.1:%d' % port


class Serve(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=str(pki / 'www'), **kw)

    def do_GET(self):
        if self.path == '/moved.crl':
            self.send_response(302)
            self.send_header('Location', 'http://169.254.169.254/latest/')
            self.end_headers()
            return
        if self.path == '/huge.crl':
            self.send_response(200)
            self.send_header('Content-Length', str(isemon.CL_CRL_MOST + 1))
            self.end_headers()
            return
        super().do_GET()

    def log_message(self, *a):
        pass


srv = http.server.ThreadingHTTPServer(('127.0.0.1', port), Serve)
threading.Thread(target=srv.serve_forever, daemon=True).start()


def pem(name):
    return (pki / ('%s.pem' % name)).read_text()


def refused(name, cas='cas.pem'):
    try:
        isemon.cl_cert_check(pem(name), str(pki / cas))
        return None
    except isemon.CertLoginError as e:
        return e.kind, str(e)


print('where a CRL is fetched from')
os.environ.pop('ISEMON_CDP_LOOPBACK_OK', None)
for bad in ('https://pki.corp.example/x.crl', 'ldap:///CN=x', 'http://u:p@pki/x.crl',
            'http://169.254.169.254/', 'http://[::ffff:169.254.169.254]/',
            'http://metadata.google.internal/', 'http://0.0.0.0/', 'http://224.0.0.1/',
            'http://127.0.0.1/', 'http://100.100.100.200/', 'http://[fe80::1]/'):
    ok('refused: %s' % bad, isemon.cl_cdp_ok(bad), False)
for good in ('http://10.1.2.3/x.crl', 'http://192.168.1.1/', 'http://[fd12::1]/',
             'http://pki.corp.example/CertEnroll/x.crl'):
    ok('taken: %s' % good, isemon.cl_cdp_ok(good), True)
for odd in ('http://2852039166/', 'http://0251.0376.0251.0376/', 'http://127.1/'):
    try:
        isemon.cl_http_get(odd)
        ok('refused as the resolver reads it: %s' % odd, False)
    except ValueError as e:
        ok('refused as the resolver reads it: %s' % odd, 'no CRL is fetched' in str(e)
           or 'not an address' in str(e))
ok('the test CRLs on 127.0.0.1 refused without the tests\' switch',
   (refused('alice') or ('', ''))[0], 'certificate')
os.environ['ISEMON_CDP_LOOPBACK_OK'] = '1'
isemon.CL_CRL_CACHE.clear()
for path, why in (('/moved.crl', 'redirect'), ('/huge.crl', 'larger than')):
    try:
        isemon.cl_http_get(U + path)
        ok('refused: %s' % why, False)
    except ValueError as e:
        ok('refused: %s (%s)' % (why, str(e)[:60]), why in str(e))
try:
    isemon.cl_http_get(U + '/moved.crl')
except ValueError as e:
    ok('no redirect followed, and it says where to', 'http://169.254.169.254' in str(e))

print('a sign-in: the certificate, its delta, the authorities above')
ok('alice: signs in', refused('alice'), None)
ok('bob: revoked in the base CRL', (refused('bob-revoked') or ('',))[0], 'revoked')
ok('carol: run out, before any CRL', (refused('carol-old') or ('',))[0], 'expired')
ok('dave: his CRL not to be had - refused', (refused('dave-nocdp') or ('',))[0], 'unavailable')
ok('erin: revoked in the delta CRL only', (refused('erin-delta') or ('',))[0], 'revoked')
f = refused('frank-sub', 'cas-sub.pem')
ok('frank: his authority revoked by the root', (f or ('',))[0], 'certificate')
ok('...said as an authority above him', 'an authority above it' in (f or ('', ''))[1], True)
ok('the root\'s CRL was fetched for the issuing authority', U + '/root.crl' in isemon.CL_CRL_CACHE,
   True)
ok('the delta fetched and known as one', isemon.CL_CRL_CACHE.get(
    U + '/issuing-delta.crl', {}).get('delta'), True)
base = isemon.CL_CRL_CACHE[U + '/issuing.crl']
ok('a CRL\'s facts: issuer, number, this < now < next, revoked, size, signature',
   (base['issuer'].endswith('CN=Corp Issuing CA') or 'Corp Issuing CA' in base['issuer'],
    base['number'].startswith('0x'), base['this'] < time.time() < base['next'],
    base['revoked'] >= 1, base['size'] > 100, base['sig']), (True, True, True, True, True, 'ok'))
ok('...the signature checked when the authorities are given',
   isemon.cl_crl_sig(base['pem'], str(pki / 'cas.pem')), 'ok')
ok('...and not checked by an authority not among them',
   isemon.cl_crl_sig(base['pem'], str(pki / 'root.pem')), 'unknown')

print('kept ten minutes, the last good one while the address does not answer')
# alice revoked and published: a sign-in alone keeps the CRL it has.
cnf = str(pki / 'ca.cnf')
subprocess.run(['openssl', 'ca', '-config', cnf, '-revoke', str(pki / 'alice.pem')],
               capture_output=True, cwd=str(pki), env=dict(os.environ, UPN='x'))
subprocess.run(['openssl', 'ca', '-config', cnf, '-gencrl', '-out', str(pki / 'new.crl.pem')],
               capture_output=True, cwd=str(pki), env=dict(os.environ, UPN='x'))
saved = (pki / 'www' / 'issuing.crl').read_bytes()
subprocess.run(['openssl', 'crl', '-in', str(pki / 'new.crl.pem'), '-outform', 'DER', '-out',
                str(pki / 'www' / 'issuing.crl')], capture_output=True)
ok('a revocation published: still taken from the CRL kept', refused('alice'), None)
with isemon.CL_CRL_LOCK:
    for c in isemon.CL_CRL_CACHE.values():
        c['at'] -= 601
ok('...ten minutes on, the new CRL: revoked', (refused('alice') or ('',))[0], 'revoked')
(pki / 'www' / 'issuing.crl').write_bytes(saved)
isemon.CL_CRL_CACHE.clear()
ok('alice back', refused('alice'), None)
(pki / 'www' / 'issuing.crl').rename(pki / 'www' / 'issuing.crl.away')
with isemon.CL_CRL_LOCK:
    for c in isemon.CL_CRL_CACHE.values():
        c['at'] -= 601
ok('its address gone: the last good one kept until its next update', refused('alice'), None)
kept = isemon.CL_CRL_CACHE[U + '/issuing.crl']
ok('...the error said', ('HTTP 404' in kept['err'], bool(kept['pem'])), (True, True))
ok('...not asked again within a minute', isemon.cl_crl_fetch(U + '/issuing.crl')['tried'],
   kept['tried'])
with isemon.CL_CRL_LOCK:
    isemon.CL_CRL_CACHE[U + '/issuing.crl']['next'] = time.time() - 1
ok('...its next update passed: nobody signs in', (refused('alice') or ('',))[0], 'unavailable')
(pki / 'www' / 'issuing.crl.away').rename(pki / 'www' / 'issuing.crl')
isemon.CL_CRL_CACHE.clear()
(pki / 'www' / 'issuing-delta.crl').rename(pki / 'www' / 'issuing-delta.crl.away')
ok('a delta named and not to be had: refused', (refused('erin-delta') or ('',))[0], 'unavailable')
ok('...one without a delta still signs in', refused('alice'), None)
(pki / 'www' / 'issuing-delta.crl.away').rename(pki / 'www' / 'issuing-delta.crl')
isemon.CL_CRL_CACHE.clear()

print('the card')
isemon.CONFIG['certlogin'] = 1
daemon.certlogin_put((pki / 'cas.pem').read_text(), 'boss')
v = daemon.certlogin_view(True)
rows = {r['url']: r for r in v['crls']}
ok('the root\'s CRL, named by the issuing authority, not fetched yet',
   (rows.get(U + '/root.crl', {}).get('fetched'), rows.get(U + '/root.crl', {}).get('named'),
    any('Corp Issuing CA' in x for x in rows.get(U + '/root.crl', {}).get('of') or [])),
   (False, True, True))
ok('no authority without a CRL over http', v['blind'], [])
ca = daemon.certlogin_ca_file()
ok('erin refused by the card\'s authorities too', (refused('erin-delta') or ('',))[0], 'revoked')
ok('alice signs in by them', isemon.cl_cert_check(pem('alice'), str(ca))['upn'],
   ['alice@corp.example'])
v = daemon.certlogin_view(True)
rows = {r['url']: r for r in v['crls']}
r = rows.get(U + '/issuing.crl') or {}
ok('a row fetched: issuer, number, revoked, size, signature, this server',
   (r.get('fetched'), r.get('ok'), (r.get('number') or '').startswith('0x'),
    (r.get('revoked') or 0) >= 1, (r.get('size') or 0) > 100, r.get('sig'),
    [n['node'] for n in r.get('nodes') or []]),
   (True, True, True, True, True, 'ok', [isemon.db_node_name()]))
ok('never a CRL on the card', 'BEGIN X509 CRL' in json.dumps(v), False)

print('Fetch now, Clear: a full administrator only')
PORT = 24000 + random.randint(0, 3000)
isemon.CONFIG['api_port'] = PORT
api = isemon.ApiServer(daemon, PORT)
api.start()
time.sleep(0.4)
isemon.TOKEN_FILE.write_text(isemon.API_TOKEN + '\n')


def call(path, method='GET', payload=None, session=None):
    req = urllib.request.Request('http://127.0.0.1:%d%s' % (PORT, path),
                                 data=json.dumps(payload).encode() if payload is not None
                                 else None, method=method)
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


def wait(ident, session):
    for _ in range(60):
        _s, r = call('/api/certlogin', 'POST', {'action': 'result', 'id': ident}, session)
        got = list((r.get('nodes') or {}).values())
        if got and all(got):
            return got[0]
        time.sleep(0.5)
    return None


try:
    daemon.add_user('boss', 'a-long-enough-password', 'fulladmin')
    daemon.add_user('watcher', 'another-long-password', 'readonly')
    boss = call('/api/auth/login', 'POST', {'name': 'boss',
                                            'password': 'a-long-enough-password'})[1]['token']
    watcher = call('/api/auth/login', 'POST', {'name': 'watcher',
                                               'password': 'another-long-password'})[1]['token']
    s, v = call('/api/certlogin', session=watcher)
    ok('read only reads the card', (s, bool(v.get('crls')), v.get('may')), (200, True, False))
    for act in ('crl_fetch', 'crl_clear', 'result'):
        s, _v = call('/api/certlogin', 'POST', {'action': act, 'url': ''}, session=watcher)
        ok('read only may not: %s' % act, s, 403)
    s, v = call('/api/certlogin', 'POST', {'action': 'crl_fetch', 'url': U + '/nowhere.crl'},
                session=boss)
    ok('an address not known: 404', (s, 'no CRL at that address' in v.get('error', '')),
       (404, True))
    # A newly published CRL: Fetch now takes it, a sign-in alone keeps the one it has.
    subprocess.run(['openssl', 'ca', '-config', cnf, '-gencrl', '-out',
                    str(pki / 'new2.crl.pem')], capture_output=True, cwd=str(pki), env=dict(os.environ, UPN='x'))
    subprocess.run(['openssl', 'crl', '-in', str(pki / 'new2.crl.pem'), '-outform', 'DER',
                    '-out', str(pki / 'www' / 'issuing.crl')], capture_output=True)
    was = isemon.CL_CRL_CACHE[U + '/issuing.crl']['number']
    s, v = call('/api/certlogin', 'POST', {'action': 'crl_fetch', 'url': ''}, session=boss)
    ok('Fetch now asked', (s, bool(v.get('id')), v.get('nodes')), (200, True,
                                                                   [isemon.db_node_name()]))
    a = wait(v.get('id'), boss) or {}
    ok('...answered: every CRL fetched', (a.get('ok'), len(a.get('crls') or []) >= 3),
       (True, True))
    ok('...the new CRL taken (a higher number)',
       int(isemon.CL_CRL_CACHE[U + '/issuing.crl']['number'], 16) > int(was, 16), True)
    ok('...the root\'s and the delta among them', {U + '/root.crl', U + '/issuing-delta.crl'}
       <= {x['url'] for x in a.get('crls') or []}, True)
    ok('...an event', store.db.execute(
        "SELECT COUNT(*) FROM events WHERE detail LIKE 'boss asked to fetch every CRL%'"
    ).fetchone()[0], 1)
    s, v = call('/api/certlogin', 'POST', {'action': 'crl_clear', 'url': U + '/issuing.crl'},
                session=boss)
    a = wait(v.get('id'), boss) or {}
    ok('Clear one', ([x['url'] for x in a.get('crls') or []],
                     U + '/issuing.crl' in isemon.CL_CRL_CACHE), ([U + '/issuing.crl'], False))
    s, v = call('/api/certlogin', 'POST', {'action': 'crl_clear', 'url': ''}, session=boss)
    a = wait(v.get('id'), boss) or {}
    ok('Clear all: nothing kept', (a.get('ok'), len(isemon.CL_CRL_CACHE)), (True, 0))
    s, v = call('/api/certlogin', session=boss)
    ok('...the root\'s CRL still named, not fetched yet', [
        (r['fetched'], r['named']) for r in v['crls'] if r['url'] == U + '/root.crl'],
        [(False, True)])
    ok('...an event', store.db.execute(
        "SELECT COUNT(*) FROM events WHERE detail LIKE 'boss cleared the CRLs%'").fetchone()[0], 1)

    print('the person is told little; why goes to Events')
    s, v = call('/api/auth/cert', 'POST', {'cert': pem('bob-revoked')})
    ok('revoked', (s, v.get('error')), (401, 'Certificate sign-in refused: revoked'))
    s, v = call('/api/auth/cert', 'POST', {'cert': pem('dave-nocdp')})
    ok('not to be had', (s, v.get('error')), (401, 'Certificate sign-in refused: not available '
                                                   'just now'))
    ok('...the reason in Events', store.db.execute(
        "SELECT COUNT(*) FROM events WHERE detail LIKE '%nowhere.crl could not be had%'"
    ).fetchone()[0] >= 1, True)

    print('the command line')
    daemon.certlogin_crl_do('clear', 'http://127.0.0.1:%d/nowhere.crl' % (port + 1))

    def cli(**kw):
        args = argparse.Namespace(cert_login_crl=False, cert_login_crl_fetch=None,
                                  cert_login_crl_clear=None, json=False, yes=False)
        for k, x in kw.items():
            setattr(args, k, x)
        out = io.StringIO()
        with redirect_stdout(out):
            rc = isemon.cmd_cert_login_crl(args, isemon.Palette(False, stream=out), store)
        return rc, out.getvalue()
    rc, out = cli(cert_login_crl_fetch='')
    ok('--cert-login-crl-fetch', (rc, 'fetched' in out), (0, True))
    rc, out = cli(cert_login_crl=True)
    ok('--cert-login-crl', (rc, 'issued by' in out and 'CRL ' + U + '/issuing.crl' in out),
       (0, True))
    rc, out = cli(cert_login_crl=True, json=True)
    ok('--cert-login-crl --json', (rc, U + '/root.crl' in [c['url'] for c in json.loads(
        out)['crls']]), (0, True))
    rc, out = cli(cert_login_crl_fetch=U + '/elsewhere.crl')
    ok('an address not known', (rc, 'no CRL at that address' in out), (1, True))
    rc, out = cli(cert_login_crl_clear='', yes=True)
    ok('--cert-login-crl-clear --yes', (rc, 'cleared' in out, len(isemon.CL_CRL_CACHE)),
       (0, True, 0))
finally:
    api.stop() if hasattr(api, 'stop') else None
    srv.shutdown()

print('the page')
page = (ROOT / 'web' / 'index.php').read_text()
for what in ('function certCrls(', 'function certCrlState(', 'function redrawKeepingPlace(',
             "'crl_' + act", "tr.dataset.key = 'row:' + c.url", 'cert-crl-said',
             '@media (max-width:640px)'):
    ok('the page has %s' % what, what in page)
ok('no scrollIntoView in the CRL table', 'scrollIntoView' in page[page.index(
    'function crlTag('):page.index('function drawCertLogin(')], False)

shutil.rmtree(str(folder), ignore_errors=True)
print('\n%d passed, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
