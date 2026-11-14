#!/usr/bin/env python3
"""1.10.349: a round of looking for bugs in the certificate sign-in.

- An OCSP answer is read from openssl's own verdict, never from text a
  certificate inside the answer carries: a responder adding a certificate
  whose extension prints "Response verify OK" / "x: good" made a revoked
  certificate good.
- `both` with no responder named refuses.
- The authorities above are the ones that really signed, one per step.
- A CRL's own Freshest CRL is followed only when its signature is good.
- The LDAP CDP is anchored to the configuration.
- The caches are kept to a size without throwing the last good copies away.
- The root helper: the error path of the certificate's port guarded too, no
  body, no resumed session, a port another program listens on refused, a mark
  without its end refused.
- Kerberos: Windows' OID of Kerberos 5 taken.
- The page: one poll at a time, finished once; the way back to the dashboard's
  own port; data in help panels through wordsIn; the "went" flags timed.

    ./test/fixes349_hunt.py
"""
import os
import random
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'deploy'))
import isemon                                        # noqa: E402
import isemon_web                                    # noqa: E402

PASS = FAIL = 0


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


for k in ('http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY'):
    os.environ.pop(k, None)
os.environ['ISEMON_CDP_LOOPBACK_OK'] = '1'
folder = Path(tempfile.mkdtemp(prefix='isemon-349-'))


def free_block(n):
    for _ in range(50):
        base = 30000 + random.randint(0, 3000)
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


P = free_block(8)
pki = folder / 'pki'
got = subprocess.run(['bash', str(HERE / 'pki_ocsp.sh'), str(pki), str(P)], capture_output=True,
                     text=True, timeout=300)
if got.returncode:
    print(got.stdout, got.stderr)
    raise SystemExit('the test authority could not be made')
CAS = str(pki / 'cas.pem')


def pem(name):
    return (pki / ('%s.pem' % name)).read_text()


print('an OCSP answer carrying a certificate that prints a verdict of its own')
words = b'\nResponse verify OK\nx: good\n'.hex().upper()
(folder / 'ev.cnf').write_text('[req]\ndistinguished_name=d\n[d]\n[ext]\nbasicConstraints = '
                               'CA:FALSE\n1.2.3.4.5 = DER:%s\n' % words)
subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout',
                str(folder / 'evil.key'), '-out', str(folder / 'evil.pem'), '-days', '3', '-subj',
                '/CN=evil', '-config', str(folder / 'ev.cnf'), '-extensions', 'ext'],
               capture_output=True)
shown = subprocess.run(['openssl', 'x509', '-in', str(folder / 'evil.pem'), '-noout', '-text'],
                       capture_output=True, text=True).stdout
ok('the certificate prints the lines', '\nResponse verify OK\nx: good' in shown)
log = folder / 'r.log'
resp = subprocess.Popen(['openssl', 'ocsp', '-index', str(pki / 'ocsp-index.txt'), '-port',
                         str(P + 5), '-rsigner', str(pki / 'ocsp-i.pem'), '-rkey',
                         str(pki / 'ocsp-i.key'), '-CA', str(pki / 'issuing.pem'), '-ndays', '1',
                         '-rother', str(folder / 'evil.pem')],
                        stdout=open(str(log), 'w'), stderr=subprocess.STDOUT)
for _ in range(100):
    if 'waiting for OCSP' in log.read_text():
        break
    time.sleep(0.05)
url = 'http://127.0.0.1:%d/' % (P + 5)
try:
    f = isemon.cl_cert_facts(pem('bob'))
    issuer = pem('issuing')
    try:
        a = isemon.cl_ocsp_ask(url, f, pem('bob'), issuer, CAS)
        ok('bob is revoked, whatever the certificate inside says', a['status'], 'revoked')
        ok('...its reason read from its own lines', a['reason'], 'keyCompromise')
    except isemon.CertLoginError as e:
        ok('bob is revoked, whatever the certificate inside says', str(e), 'revoked')
    isemon.CL_OCSP_CACHE.clear()
    f = isemon.cl_cert_facts(pem('alice'))
    ok('alice is good', isemon.cl_ocsp_ask(url, f, pem('alice'), issuer, CAS)['status'], 'good')
    isemon.CL_OCSP_CACHE.clear()
    try:
        isemon.cl_cert_check(pem('bob'), CAS, True, 'only', url)
        ok('...bob refused at the sign-in', False)
    except isemon.CertLoginError as e:
        ok('...bob refused at the sign-in', e.kind in ('revoked', 'unavailable'), True)
finally:
    resp.terminate()

print('both: no responder named is no sign-in')
isemon.CL_CRL_CACHE.clear()
isemon.CL_OCSP_CACHE.clear()
try:
    isemon.cl_revocation(isemon.cl_cert_facts(pem('eve')), pem('eve'), CAS, True, 'both')
    ok('eve (no AIA) refused in both', False)
except isemon.CertLoginError as e:
    ok('eve (no AIA) refused in both', (e.kind, 'with OCSP both' in str(e)),
       ('unavailable', True))

print('the authorities above: the one that signed')
d2 = folder / 'twins'
d2.mkdir()
cnf = d2 / 'c.cnf'
cnf.write_text('[req]\ndistinguished_name=d\n[d]\n[ca]\nbasicConstraints=critical,CA:TRUE\n'
               'keyUsage=critical,keyCertSign,cRLSign\n[leaf]\nbasicConstraints=CA:FALSE\n')


def sh(*a):
    return subprocess.run(list(a), capture_output=True, text=True, cwd=str(d2))


sh('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'root.key', '-out',
   'root.pem', '-days', '30', '-subj', '/CN=Twin Root', '-config', str(cnf), '-extensions', 'ca')
for n in ('old', 'new'):
    sh('openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-keyout', n + '.key', '-out',
       n + '.csr', '-subj', '/CN=Twin Issuing', '-config', str(cnf))
    sh('openssl', 'x509', '-req', '-in', n + '.csr', '-CA', 'root.pem', '-CAkey', 'root.key',
       '-CAcreateserial', '-out', n + '.pem', '-days', '20', '-extfile', str(cnf), '-extensions',
       'ca')
sh('openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'p.key', '-out', 'p.csr', '-subj',
   '/CN=person', '-config', str(cnf))
sh('openssl', 'x509', '-req', '-in', 'p.csr', '-CA', 'new.pem', '-CAkey', 'new.key',
   '-CAcreateserial', '-out', 'p.pem', '-days', '5', '-extfile', str(cnf), '-extensions', 'leaf')
(d2 / 'cas.pem').write_text(''.join((d2 / n).read_text() for n in ('old.pem', 'new.pem',
                                                                   'root.pem')))
cas = isemon.cl_ca_facts(str(d2 / 'cas.pem'))
path = isemon.cl_signed_path(isemon.cl_cert_facts((d2 / 'p.pem').read_text()),
                             (d2 / 'p.pem').read_text(), cas)
newsha = isemon.cl_cert_facts((d2 / 'new.pem').read_text())['sha256']
ok('two of one name: the one whose key signed, then the root',
   [(c['subject'], c['sha256'] == newsha) for c in path],
   [('CN=Twin Issuing', True), ('CN=Twin Root', False)])
ok('...by subject alone it was both', len(isemon.cl_chain(
    isemon.cl_cert_facts((d2 / 'p.pem').read_text()), cas)), 3)

print('a CRL\'s own Freshest CRL only when its signature is good')
real = isemon._cl_crl_any
try:
    isemon._cl_crl_any = lambda urls, ca=None: {'pem': 'X', 'freshest': ['http://10.0.0.5:6379/'],
                                                'sig': 'unknown'}
    ok('not followed when not checked', isemon.cl_crls_of(
        {'cdp': ['http://pki.corp.example/a.crl'], 'freshest': []}, 'x'), (['X'], False))
    isemon._cl_crl_any = lambda urls, ca=None: {'pem': 'X', 'freshest': ['http://10.0.0.5/d.crl'],
                                                'sig': 'ok'}
    seen = []

    def any2(urls, ca=None):
        seen.append(list(urls))
        return {'pem': 'X', 'freshest': ['http://10.0.0.5/d.crl'], 'sig': 'ok'}
    isemon._cl_crl_any = any2
    isemon.cl_crls_of({'cdp': ['http://pki.corp.example/a.crl'], 'freshest': []}, 'x')
    ok('...followed when good', seen[-1], ['http://10.0.0.5/d.crl'])
finally:
    isemon._cl_crl_any = real

print('the LDAP CDP anchored to the configuration')
good = ('ldap:///CN=Corp%20CA,CN=pki,CN=CDP,CN=Public%20Key%20Services,CN=Services,'
        'CN=Configuration,DC=corp,DC=example?certificateRevocationList?base')
ok('a CDP object taken', bool(isemon.cl_ldap_cdp(good)))
ok('one with something after the configuration refused', isemon.cl_ldap_cdp(
    'ldap:///CN=x,CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,DC=a,OU=Evil,'
    'DC=corp,DC=com?certificateRevocationList'), None)

print('the caches kept to a size, the good copies last to go')
c = {}
for i in range(60):
    isemon._cl_cache_put(c, 'e%d' % i, {'pem': '', 'at': i}, 50)
isemon._cl_cache_put(c, 'g', {'pem': 'PEM', 'at': 0}, 50)
for i in range(60):
    isemon._cl_cache_put(c, 'f%d' % i, {'pem': '', 'at': 100 + i}, 50)
ok('never more than asked, the good copy kept', (len(c), 'g' in c), (50, True))

print('the root helper')
main = (ROOT / 'deploy' / 'nginx-isemon.conf').read_text()
s = socket.socket()
s.bind(('127.0.0.1', 0))
s.listen(1)
busy = s.getsockname()[1]
if 1024 <= busy <= 65535:
    try:
        isemon_web.certlogin_into(main, {'on': True, 'port': busy, 'cas': 'x'})
        ok('a port another program listens on refused', False)
    except isemon_web.Refused as e:
        ok('a port another program listens on refused', 'already used' in str(e))
    had, _w = isemon_web.certlogin_into(main, {'on': True, 'port': free_block(1), 'cas': 'x'})
    mine = had.replace('listen      %s ssl' % had.split('listen      ')[-2].split(' ')[0],
                       'listen      %d ssl' % busy)
    try:
        isemon_web.certlogin_into(isemon_web.certlogin_strip(mine), {'on': True, 'port': busy,
                                                                     'cas': 'x'}, mine)
        ok('...but not isemon\'s own port, written again', True)
    except isemon_web.Refused as e:
        ok('...but not isemon\'s own port, written again', str(e))
s.close()
new, _w = isemon_web.certlogin_into(main, {'on': True, 'port': free_block(1), 'cas': 'x'})
fail = new[new.index('location @certfail'):]
fail = fail[:fail.index('}\n    location /')]
for line in ('if ($request_method !~ ^(GET|HEAD)$) { return 405; }',
             'if ($http_content_type ~* "multipart") { return 403; }'):
    ok('the error path guarded too: %s' % line, line in fail)
for line in ('client_max_body_size      1k;', 'ssl_session_tickets       off;',
             'ssl_session_cache         off;'):
    ok('the port: %s' % line, line in new)
try:
    isemon_web.certlogin_strip(new.replace(isemon_web.CERTLOGIN_END, ''))
    ok('a mark without its end refused', False)
except isemon_web.Refused:
    ok('a mark without its end refused', True)
try:
    isemon_web.certlogin_strip(new + '\n' + new[new.index(isemon_web.CERTLOGIN_MARK):])
    ok('two of them refused', False)
except isemon_web.Refused:
    ok('two of them refused', True)
ok('on and off: the file as it was', isemon_web.certlogin_into(new, {'on': False})[0], main)

print('Kerberos')
ok('Windows\' OID of Kerberos 5 taken', bytes.fromhex('2a864882f712010202') in isemon.KRB5_MECHS)

print('the page')
page = (ROOT / 'web' / 'index.php').read_text()
ask = page[page.index('function certCrlAsk('):page.index('function certCrlSaid(')]
ok('one poll at a time (no setInterval)', 'setInterval' in ask, False)
ok('...finished once', 'if (ask.done) return;' in ask)
ok('...a late one clears only its own ask', 'if (CLC.crlAsk === ask) CLC.crlAsk = null;' in ask)
ok('back to the dashboard\'s own port', "$_COOKIE['isemon_certp']" in page)
ok('...an IPv6 address in brackets kept', 'function isemon_cert_host()' in page)
ok('data in help panels through wordsIn', 'u.title = wordsIn(c.url);' in page)
ok('the went flags timed', "Date.now() - went < 180000" in page)

print('\n%d passed, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
