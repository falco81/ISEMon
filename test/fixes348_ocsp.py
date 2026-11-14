#!/usr/bin/env python3
"""1.10.348: OCSP and CRLs from the directory for the sign-in with a
certificate. A test PKI (test/pki_ocsp.sh) with two OCSP responders (openssl
ocsp), a CRL over http, and a certificate whose only CRL Distribution Point is
in the directory (ldap:///...CN=CDP...). Checked: off / first / only / both,
the authorities above, a responder that does not answer, one that does not
know a certificate, a forged answer, a responder of its own, the ten-minute
cache and the last good answer, the setting's guards, the CRL read from the
directory (and nothing else read there), the card, Ask again and Clear (a full
administrator only), the events, and the command line.

    ./test/fixes348_ocsp.py
"""
import argparse
import http.server
import io
import json
import os
import random
import shutil
import socket
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


folder = Path(tempfile.mkdtemp(prefix='isemon-348-'))
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
os.environ['ISEMON_CDP_LOOPBACK_OK'] = '1'
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)


def free_block(n):
    for _ in range(50):
        base = 27000 + random.randint(0, 3000)
        good = True
        for p in range(base, base + n):
            s = socket.socket()
            try:
                s.bind(('127.0.0.1', p))
            except OSError:
                good = False
            finally:
                s.close()
        if good:
            return base
    raise SystemExit('no free ports')


P = free_block(6)
pki = folder / 'pki'
got = subprocess.run(['bash', str(HERE / 'pki_ocsp.sh'), str(pki), str(P)], capture_output=True,
                     text=True, timeout=300)
if got.returncode:
    print(got.stdout, got.stderr)
    raise SystemExit('the test authority could not be made')
ISS, ROOTR, DEAD, FORGE = 'http://127.0.0.1:%d/' % (P + 2), 'http://127.0.0.1:%d/' % (P + 1), \
    'http://127.0.0.1:%d/' % (P + 3), 'http://127.0.0.1:%d/' % (P + 4)


class Serve(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=str(pki / 'www'), **kw)

    def log_message(self, *a):
        pass


srv = http.server.ThreadingHTTPServer(('127.0.0.1', P), Serve)
threading.Thread(target=srv.serve_forever, daemon=True).start()
# A responder of somebody else's: its own key, an answer no authority put in signed.
subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout',
                str(pki / 'forge.key'), '-out', str(pki / 'forge.pem'), '-days', '3', '-subj',
                '/CN=Forger'], capture_output=True)
RESP = {}


def responder(name, port, index, signer, key, ca):
    # Its log says when it listens: a bare connection to see whether it is up
    # holds openssl's one-at-a-time responder until it times out.
    log = folder / ('ocsp-%s.log' % name)
    RESP[name] = subprocess.Popen(
        ['openssl', 'ocsp', '-index', str(index), '-port', str(port), '-rsigner', str(signer),
         '-rkey', str(key), '-CA', str(ca), '-ndays', '1'],
        stdout=open(str(log), 'w'), stderr=subprocess.STDOUT)
    RESP[name].log = log


def up(port):
    name = next((n for n, p in RESP.items() if ' %d ' % port in ' '.join(p.args) + ' '), None)
    for _ in range(100):
        try:
            if 'waiting for OCSP client' in RESP[name].log.read_text():
                return True
        except (OSError, KeyError):
            pass
        time.sleep(0.05)
    return False


responder('iss', P + 2, pki / 'ocsp-index.txt', pki / 'ocsp-i.pem', pki / 'ocsp-i.key',
          pki / 'issuing.pem')
responder('root', P + 1, pki / 'rootdb' / 'index.txt', pki / 'ocsp-r.pem', pki / 'ocsp-r.key',
          pki / 'root.pem')
responder('forge', P + 4, pki / 'ocsp-index.txt', pki / 'forge.pem', pki / 'forge.key',
          pki / 'issuing.pem')
ok('the responders are up', all(up(p) for p in (P + 1, P + 2, P + 4)))
CAS = str(pki / 'cas.pem')


def pem(name):
    return (pki / ('%s.pem' % name)).read_text()


def check(name, mode, url=''):
    try:
        f = isemon.cl_cert_check(pem(name), CAS, True, mode, url)
        return 'ok:' + '+'.join(f['revocation'])
    except isemon.CertLoginError as e:
        return e.kind


def fresh():
    isemon.CL_CRL_CACHE.clear()
    isemon.CL_OCSP_CACHE.clear()


try:
    print('what a certificate says of OCSP')
    ok('alice names her responder (AIA)', isemon.cl_cert_facts(pem('alice'))['ocsp'], [ISS])
    ok('...the issuing authority its own', isemon.cl_cert_facts(pem('issuing'))['ocsp'], [ROOTR])
    ok('eve names none', isemon.cl_cert_facts(pem('eve'))['ocsp'], [])

    print('off: the CRLs alone, as before')
    fresh()
    ok('alice', check('alice', 'off'), 'ok:crl')
    ok('bob: revoked', check('bob', 'off'), 'revoked')
    ok('hal: revoked in the CRL', check('hal', 'off'), 'revoked')
    ok('...no responder was asked', isemon.CL_OCSP_CACHE, {})

    print('first: OCSP, the CRL when the responder does not answer')
    fresh()
    ok('alice: by OCSP, for her and the authority above', check('alice', 'first'), 'ok:ocsp+ocsp')
    ok('bob: revoked, the responder says', check('bob', 'first'), 'revoked')
    ok('dan: his responder dead - by his CRL', check('dan', 'first'), 'ok:crl+ocsp')
    ok('eve: no responder named - by her CRL', check('eve', 'first'), 'ok:crl+ocsp')
    ok('ida: the responder does not know her - refused', check('ida', 'first'), 'certificate')
    ok('hal: the responder (older) says good, the CRL is not asked', check('hal', 'first'),
       'ok:ocsp+ocsp')
    a = isemon.CL_OCSP_CACHE[isemon.cl_ocsp_key(ISS, isemon.cl_cert_facts(pem('bob')))]
    ok('...bob\'s answer: revoked, its reason and time, the responder that signed',
       (a['status'], a['reason'], bool(a['revoked_at']), 'Corp Issuing OCSP' in a['responder'],
        a['this'] < time.time() < a['next']), ('revoked', 'keyCompromise', True, True, True))

    print('only: OCSP alone')
    fresh()
    ok('alice', check('alice', 'only'), 'ok:ocsp+ocsp')
    ok('dan: no answer, no sign-in', check('dan', 'only'), 'unavailable')
    ok('eve: no responder, no sign-in', check('eve', 'only'), 'unavailable')
    fresh()
    ok('...(the one set is asked for the authority above too - not its responder: no answer)',
       check('alice', 'only', ISS), 'unavailable')
    print('    (%s)' % '; '.join(c['err'] for c in isemon.cl_ocsp_now() if c['err']))
    ok('...it said why', any(c['err'] for c in isemon.cl_ocsp_now()), True)

    print('both: OCSP and the CRL')
    fresh()
    ok('alice', check('alice', 'both'), 'ok:ocsp+crl+ocsp+crl')
    ok('hal: good by OCSP, revoked by the CRL - refused', check('hal', 'both'), 'revoked')
    ok('dan: no answer - refused', check('dan', 'both'), 'unavailable')

    print('an answer not signed by the authorities put in')
    fresh()
    try:
        isemon.cl_cert_check(pem('alice'), CAS, True, 'only', FORGE)
        ok('a forged answer refused', False)
    except isemon.CertLoginError as e:
        ok('a forged answer refused', (e.kind, 'signature is not good' in str(e)),
           ('unavailable', True))

    print('kept ten minutes, the last good answer while the responder does not answer')
    fresh()
    ok('alice', check('alice', 'only'), 'ok:ocsp+ocsp')
    RESP['iss'].terminate()
    RESP['iss'].wait()
    ok('the responder stopped: the answer kept is used', check('alice', 'only'), 'ok:ocsp+ocsp')
    with isemon.CL_OCSP_LOCK:
        for c in isemon.CL_OCSP_CACHE.values():
            c['at'] -= 601
    ok('...ten minutes on: the last good answer until its next update', check('alice', 'only'),
       'ok:ocsp+ocsp')
    k = isemon.cl_ocsp_key(ISS, isemon.cl_cert_facts(pem('alice')))
    ok('...the error said', bool(isemon.CL_OCSP_CACHE[k]['err']), True)
    with isemon.CL_OCSP_LOCK:
        isemon.CL_OCSP_CACHE[k]['next'] = time.time() - 1
    ok('...its next update passed: only - no sign-in', check('alice', 'only'), 'unavailable')
    ok('...first - by the CRL', check('alice', 'first'), 'ok:crl+ocsp')
    responder('iss', P + 2, pki / 'ocsp-index.txt', pki / 'ocsp-i.pem', pki / 'ocsp-i.key',
              pki / 'issuing.pem')
    up(P + 2)

    print('the responder of its own: the same guards as a CRL\'s address')
    for bad in ('http://169.254.169.254/', 'https://pki.corp.example/ocsp',
                'http://u:p@pki/ocsp', 'http://127.0.0.1/', 'ldap:///x'):
        os.environ.pop('ISEMON_CDP_LOOPBACK_OK')
        try:
            isemon.check_setting('certlogin_ocsp_url', bad) if hasattr(isemon, 'check_setting') \
                else daemon.save_settings({'certlogin_ocsp_url': bad}, by='boss')
            ok('refused: %s' % bad, False)
        except ValueError:
            ok('refused: %s' % bad, True)
        os.environ['ISEMON_CDP_LOOPBACK_OK'] = '1'
    daemon.save_settings({'certlogin_ocsp_url': 'http://pki.corp.example/ocsp'}, by='boss')
    ok('taken: http://pki.corp.example/ocsp', isemon.CONFIG['certlogin_ocsp_url'],
       'http://pki.corp.example/ocsp')
    daemon.save_settings({'certlogin_ocsp_url': ''}, by='boss')

    print('a CRL from the directory')
    gina = isemon.cl_cert_facts(pem('gina'))
    ok('gina\'s only CDP is in the directory', gina['cdp'][0].startswith('ldap:///CN=Corp%20'), True)
    got = isemon.cl_ldap_cdp(gina['cdp'][0])
    ok('...read as its DN and attribute', got, (
        'CN=Corp Issuing CA,CN=pki,CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,'
        'DC=corp,DC=example', 'certificateRevocationList'))
    for bad in ('ldap:///CN=Administrator,CN=Users,DC=corp,DC=example?userPassword',
                'ldap:///CN=x,CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,'
                'DC=corp,DC=example?unicodePwd',
                'ldap:///CN=x,CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,'
                'DC=corp,DC=example?certificateRevocationList?sub',
                'ldap:///CN=x,CN=Users,DC=corp,DC=example?certificateRevocationList'):
        ok('nothing else read: %s' % bad[:60], isemon.cl_ldap_cdp(bad), None)
    ASKED = []
    crl_der = (pki / 'www' / 'issuing.crl').read_bytes()

    class Link:
        def search(self, base, flt, attrs=(), scope=2, limit=200, paged=False):
            ASKED.append((base, tuple(attrs), scope))
            return [{'dn': base, 'attrs': {}, 'raw': {'certificateRevocationList;binary':
                                                      [crl_der]}}]

        def close(self):
            pass
    daemon.directory_reader = lambda *a, **kw: Link()
    isemon.CONFIG['certlogin'] = 1
    daemon.certlogin_put((pki / 'cas.pem').read_text(), 'boss')
    fresh()
    daemon.certlogin_ldap_on()
    try:
        isemon.cl_cert_check(pem('gina'), str(daemon.certlogin_ca_file()))
        ok('off: gina refused - no CRL over http', False)
    except isemon.CertLoginError as e:
        ok('off: gina refused - no CRL over http', 'names no CRL over http' in str(e))
    isemon.CONFIG['certlogin_crl_ldap'] = 1
    daemon.certlogin_ldap_on()
    fresh()
    ok('on: gina signs in by the CRL read from the directory',
       isemon.cl_cert_check(pem('gina'), str(daemon.certlogin_ca_file()))['revocation'], ['crl'])
    ok('...asked of its CDP object only, that entry, its CRL attribute', ASKED[-1:], [(
        got[0], ('certificateRevocationList',), 0)])
    rows = {r['url']: r for r in daemon.certlogin_view(True)['crls']}
    ok('...a row of the card, read from the directory', rows[gina['cdp'][0]]['via'], 'ldap')
    isemon.CONFIG['certlogin_crl_ldap'] = 0
    daemon.certlogin_ldap_on()

    print('the card')
    isemon.CONFIG['certlogin_ocsp'] = 'first'
    fresh()
    for n in ('alice', 'bob', 'dan'):
        check(n, 'first')
    v = daemon.certlogin_view(True)
    ans = {(a['subject'], a['url']): a for a in v['ocsp_answers']}
    ok('the answers: alice good, bob revoked, dan none',
       (ans[('CN=alice', ISS)]['status'], ans[('CN=bob', ISS)]['status'],
        ans[('CN=dan', DEAD)]['status']), ('good', 'revoked', ''))
    ok('never a certificate on the card', 'BEGIN CERTIFICATE' in json.dumps(v), False)
    ok('the mode said', (v['ocsp'], v['ocsp_url_ok']), ('first', True))

    PORT = free_block(1)
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

    daemon.add_user('boss', 'a-long-enough-password', 'fulladmin')
    daemon.add_user('watcher', 'another-long-password', 'readonly')
    boss = call('/api/auth/login', 'POST', {'name': 'boss',
                                            'password': 'a-long-enough-password'})[1]['token']
    watcher = call('/api/auth/login', 'POST', {'name': 'watcher',
                                               'password': 'another-long-password'})[1]['token']
    for act in ('ocsp_fetch', 'ocsp_clear'):
        s, _v = call('/api/certlogin', 'POST', {'action': act, 'url': ''}, session=watcher)
        ok('read only may not: %s' % act, s, 403)
    s, v = call('/api/certlogin', 'POST', {'action': 'ocsp_fetch', 'url': 'nothing|x|1'},
                session=boss)
    ok('an answer not kept: 404', s, 404)
    s, v = call('/api/certlogin', 'POST', {'action': 'ocsp_fetch', 'url': ''}, session=boss)
    a = wait(v.get('id'), boss) or {}
    st = {x['url'] + x.get('status', ''): x['ok'] for x in a.get('crls') or []}
    ok('Ask again: every responder asked, the dead one said', (
        st.get(ISS + 'good'), st.get(ISS + 'revoked'), st.get(DEAD), a.get('ok')),
        (True, True, False, False))
    ok('...an event', store.db.execute(
        "SELECT COUNT(*) FROM events WHERE detail LIKE 'boss asked every OCSP responder%'"
    ).fetchone()[0], 1)

    print('the person is told little')
    s, v = call('/api/auth/cert', 'POST', {'cert': pem('bob')})
    ok('bob: revoked', (s, v.get('error')), (401, 'Certificate sign-in refused: revoked'))
    ok('...why in Events', store.db.execute(
        "SELECT COUNT(*) FROM events WHERE detail LIKE '%revoked, the OCSP responder says%'"
    ).fetchone()[0] >= 1, True)

    print('the command line')

    def cli(**kw):
        args = argparse.Namespace(cert_login_ocsp=False, cert_login_ocsp_fetch=False,
                                  cert_login_ocsp_clear=False, json=False, yes=False)
        for k2, x in kw.items():
            setattr(args, k2, x)
        out = io.StringIO()
        with redirect_stdout(out):
            rc = isemon.cmd_cert_login_ocsp(args, isemon.Palette(False, stream=out), store)
        return rc, out.getvalue()
    rc, out = cli(cert_login_ocsp=True)
    ok('--cert-login-ocsp', (rc, 'CN=bob  revoked' in out, 'keyCompromise' in out), (0, True, True))
    rc, out = cli(cert_login_ocsp=True, json=True)
    ok('--cert-login-ocsp --json', (rc, json.loads(out)['mode']), (0, 'first'))
    rc, out = cli(cert_login_ocsp_clear=True, yes=True)
    ok('--cert-login-ocsp-clear --yes', (rc, 'cleared' in out, len(isemon.CL_OCSP_CACHE)),
       (0, True, 0))
    ok('...an event', store.db.execute(
        "SELECT COUNT(*) FROM events WHERE detail LIKE '%cleared the OCSP answers%'"
    ).fetchone()[0], 1)

    print('the page')
    page = (ROOT / 'web' / 'index.php').read_text()
    for what in ('function certOcsp(', 'function certRevFlow(', "'certlogin_ocsp'",
                 "certlogin_ocsp_url: ['certlogin_ocsp', 'off-not']", "c.via === 'ldap'",
                 "'ocsp:' + c.key"):
        ok('the page has %s' % what, what in page)
    ok('off by default', (isemon.DEFAULTS['certlogin_ocsp'], isemon.DEFAULTS['certlogin_crl_ldap'],
                          isemon.DEFAULTS['certlogin_ocsp_url']), ('off', 0, ''))
finally:
    for p in RESP.values():
        p.terminate()
    srv.shutdown()

shutil.rmtree(str(folder), ignore_errors=True)
print('\n%d passed, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
