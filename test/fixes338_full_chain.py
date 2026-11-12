#!/usr/bin/env python3
"""1.10.338: the web server sends its whole chain. A certificate uploaded
without the intermediate authority that signed it is completed from its CA
Issuers address (DER, PEM or PKCS#7), as a browser completes it; the chain
is checked against the system's roots as a client without AIA checks it;
the card says complete or incomplete, Complete the chain does it for the
certificate in place, and the web server is asked from this machine after a
change. A small CA of its own is made here: a root, two intermediates, and
a certificate for a made-up name; the CA Issuers addresses point at a web
server of this test.

    ./test/fixes338_full_chain.py
"""
import http.server
import json
import os
import random
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
os.environ['ISEMON_WEB_HELPER'] = '1'
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


def sh(*args):
    r = subprocess.run(list(args), capture_output=True, text=True)
    if r.returncode:
        raise SystemExit('%s: %s' % (' '.join(args[:3]), r.stderr))
    return r.stdout


work = Path(tempfile.mkdtemp(prefix='isemon-338-'))
www = work / 'www'
www.mkdir()


class Quiet(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=str(www), **kw)

    def log_message(self, *a):
        pass


httpd = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Quiet)
HP = httpd.server_address[1]
threading.Thread(target=httpd.serve_forever, daemon=True).start()
BASE = 'http://127.0.0.1:%d' % HP


def mk_ca(name, cn, signer=None, aia=None, ca=True):
    key, crt, ext = (str(work / (name + x)) for x in ('.key', '.pem', '.ext'))
    sh('openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256',
       '-out', key)
    lines = ['basicConstraints=critical,CA:%s' % ('TRUE' if ca else 'FALSE'),
             'subjectKeyIdentifier=hash']
    if signer:
        lines.append('authorityKeyIdentifier=keyid')
    if ca:
        lines.append('keyUsage=critical,keyCertSign,cRLSign')
    else:
        lines += ['keyUsage=critical,digitalSignature', 'extendedKeyUsage=serverAuth',
                  'subjectAltName=DNS:%s' % cn]
    if aia:
        lines.append('authorityInfoAccess=caIssuers;URI:%s' % aia)
    Path(ext).write_text('[x]\n' + '\n'.join(lines) + '\n')
    if not signer:
        sh('openssl', 'req', '-x509', '-new', '-key', key, '-subj', '/CN=' + cn, '-days', '30',
           '-extensions', 'x', '-config', ext, '-out', crt)
    else:
        csr = str(work / (name + '.csr'))
        sh('openssl', 'req', '-new', '-key', key, '-subj', '/CN=' + cn, '-out', csr,
           '-config', ext)
        sh('openssl', 'x509', '-req', '-in', csr, '-CA', str(work / (signer + '.pem')),
           '-CAkey', str(work / (signer + '.key')), '-CAcreateserial', '-days', '20',
           '-extfile', ext, '-extensions', 'x', '-out', crt)
    return Path(crt).read_text(), Path(key).read_text()


# root -> int1 (AIA: root, DER) -> int2 (AIA: int1 as PKCS#7) -> leaf (AIA: int2, PEM)
# Ext config for req needs a [req] section: give openssl a tiny one.
Path(work / 'req.cnf').write_text('[req]\ndistinguished_name=dn\n[dn]\n')
os.environ['OPENSSL_CONF'] = str(work / 'req.cnf')
root, _ = mk_ca('root', 'Test Root R1')
int1, _ = mk_ca('int1', 'Test Issuing CA One', 'root', BASE + '/root.cer')
int2, _ = mk_ca('int2', 'Test TLS CA Two', 'int1', BASE + '/int1.p7c')
leaf, leaf_key = mk_ca('leaf', 'monitor.example.test', 'int2', BASE + '/int2.crt', ca=False)
sh('openssl', 'x509', '-in', str(work / 'root.pem'), '-outform', 'DER', '-out', str(www / 'root.cer'))
sh('openssl', 'crl2pkcs7', '-nocrl', '-certfile', str(work / 'int1.pem'), '-outform', 'DER',
   '-out', str(www / 'int1.p7c'))
(www / 'int2.crt').write_text(int2)
(work / 'bundle.pem').write_text(root)
other, _ = mk_ca('other', 'Some Other Root')
(work / 'empty.pem').write_text(other)
os.environ['ISEMON_CA_BUNDLE'] = str(work / 'bundle.pem')

print('the chain read, with nothing fetched')
st = isemon.tls_chain_state(leaf, '')
ok('the certificate alone: incomplete', st['state'], 'incomplete')
ok('...the missing one named', st['missing'], 'Test TLS CA Two')
st = isemon.tls_chain_state(leaf, int2)
ok('one of two intermediates: still incomplete', (st['state'], st['missing']),
   ('incomplete', 'Test Issuing CA One'))
st = isemon.tls_chain_state(leaf, int2 + int1)
ok('the whole chain: complete', st['state'], 'complete')
ok('...three certificates sent, up to the root', (st['n'], st['top']), (3, 'Test Root R1'))
ok('...in words', isemon.tls_chain_words(st), 'complete - 3 certificates up to Test Root R1')
ok('the root that signs itself: self-signed', isemon.tls_chain_state(root)['state'],
   'self-signed')

print('put in order, the root left out')
chain, rt, left = isemon.tls_order(leaf, root + int1 + int2)
ok('nearest first', isemon._pem_list(chain), [int2, int1])
ok('the root apart', rt, root)
ok('nothing left over', left, 0)

print('completed from CA Issuers')
new, st, added = isemon.tls_chain_complete(leaf, '')
ok('PEM, then PKCS#7: both intermediates read', added, ['Test TLS CA Two', 'Test Issuing CA One'])
ok('...the chain kept is them, nearest first', isemon._pem_list(new), [int2, int1])
ok('...and complete', st['state'], 'complete')
new, st, added = isemon.tls_chain_complete(leaf, int2)
ok('the one missing link only', added, ['Test Issuing CA One'])
new, st, added = isemon.tls_chain_complete(leaf, int2 + int1)
ok('a whole chain: nothing fetched', added, [])
(www / 'int1.p7c').rename(www / 'gone.p7c')
new, st, added = isemon.tls_chain_complete(leaf, '')
ok('a link that cannot be read: the chain as it came', new, '')
ok('...incomplete, and why said', (st['state'], 'could not be read' in st.get('why', '')),
   ('incomplete', True))
ok('...in words', isemon.tls_chain_words(st).startswith(
    'incomplete - the authority Test TLS CA Two is not sent and could not be completed ('),
   True)
(www / 'gone.p7c').rename(www / 'int1.p7c')
try:
    isemon.tls_fetch('file:///etc/passwd')
    ok('file:// refused', False)
except isemon.WebRootError:
    ok('file:// refused', True)

print('a company root kept beside it')
os.environ['ISEMON_CA_BUNDLE'] = str(work / 'empty.pem')
isemon._TLS_CHAIN_SEEN.clear()
st = isemon.tls_chain_state(leaf, int2 + int1, root)
ok('complete up to the company root', (st['state'], st['company']), ('complete', True))
ok('...in words', isemon.tls_chain_words(st).endswith(
    ' - a private root: only clients that trust it take it'), True)
os.environ['ISEMON_CA_BUNDLE'] = str(work / 'bundle.pem')
isemon._TLS_CHAIN_SEEN.clear()

print('uploaded on the page without its chain')
state = work / 'state'
(state / 'web').mkdir(parents=True)
isemon.STATE_DIR = state
isemon.DB_FILE = state / 'd.db'
isemon.RUN_DIR = state
isemon.LOG_DIR = state
isemon._LOG_PATH = state / 'd.log'
isemon.CONFIG_FILE = state / 'config.json'
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'api_port': 19000 + random.randint(0, 900), 'geo': 0, 'mikrotik1': 0})
(state / 'config.json').write_text(json.dumps({'db_engine': 'sqlite', 'db_password': 'hush'}))
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)
wr = daemon.webroot
got = wr.tls_do({'action': 'upload', 'pem': [leaf + leaf_key]}, 'admin')
ok('kept, and said complete', 'the chain: complete - 3 certificates up to Test Root R1 '
   '(fetched: Test TLS CA Two, Test Issuing CA One - it was not sent with the certificate)'
   in got['message'], True)
tls = wr.tls_conf()
ok('the chain kept is the one read', isemon._pem_list(tls['chain']), [int2, int1])
req = wr.request()
ok('root is handed cert and chain', (req['tls']['cert'], req['tls']['chain']),
   (leaf, int2 + int1))
page = wr.tls_page(True)
ok('the card: complete', (page['chain']['state'], page['chain']['n']), ('complete', 3))
ok('...and says what was fetched', page['chain']['fetched'], ['Test TLS CA Two',
                                                               'Test Issuing CA One'])

print('an upload whose chain cannot be completed: kept, with the warning said')
(www / 'int2.crt').rename(www / 'int2.gone')
got = wr.tls_do({'action': 'upload', 'pem': [leaf + leaf_key]}, 'admin')
ok('kept all the same, the warning in the message',
   'the chain: incomplete - the authority Test TLS CA Two is not sent' in got['message'],
   True)
ev = store.db.execute("SELECT level, detail FROM events WHERE detail LIKE '%refuse it%' "
                      "ORDER BY id DESC").fetchone()
ok('...and an event of it, a warning', ev and ev['level'], 'warn')
page = wr.tls_page(True)
ok('the card: incomplete, the missing one named', (page['chain']['state'],
                                                  page['chain']['missing']),
   ('incomplete', 'Test TLS CA Two'))
ok('...and why it could not be completed', 'Connection refused' in page['chain'].get('why', '')
   or 'could not be read' in page['chain'].get('why', ''), True)
got = wr.tls_do({'action': 'tls_chain'}, 'admin')
ok('Complete the chain with the address gone: complete false, and why (not an error)',
   (got['complete'], 'could not be completed' in got['message']), (False, True))
print('Upload the missing authority')
for bad, why in (('', 'no certificate'), (leaf_key, 'no private key'), (leaf, 'there already'),
                 (root, 'none of these')):
    try:
        wr.tls_do({'action': 'tls_chain_add', 'text': bad}, 'admin')
        ok('refused: ' + why, False)
    except isemon.WebRootError as e:
        ok('refused: %s (%s)' % (why, e), True)
got = wr.tls_do({'action': 'tls_chain_add', 'text': int2}, 'admin')
ok('the missing one by hand: the rest read, complete', (got['complete'], isemon._pem_list(
    wr.tls_conf()['chain'])), (True, [int2, int1]))
ev = store.db.execute("SELECT level, detail FROM events WHERE detail LIKE '%added to the chain%' "
                      "ORDER BY id DESC").fetchone()
ok('...an event of it', ev and ev['detail'].startswith('Test TLS CA Two added'), True)
(www / 'int2.gone').rename(www / 'int2.crt')
got = wr.tls_do({'action': 'tls_chain'}, 'admin')
ok('Check the chain: complete, and what was fetched said', (got['complete'], got['message']),
   (True, 'complete - 3 certificates up to Test Root R1 (fetched: Test Issuing CA One - it was '
          'not sent with the certificate)'))
ok('...kept', isemon._pem_list(wr.tls_conf()['chain']), [int2, int1])
wr.tls_do({'action': 'upload', 'pem': [leaf + int1 + root + int2 + leaf_key]}, 'admin')
ok('one PEM in any order: put in order, the root apart',
   (isemon._pem_list(wr.tls_conf()['chain']), wr.tls_conf()['root']), ([int2, int1], root))

print('acme\'s certificate: served with its chain, completed when it lacks a link')
got = isemon._acme_sorted(leaf, leaf_key)
ok('the CA sent the certificate alone: the chain read', isemon._pem_list(got['chain']),
   [int2, int1])
(www / 'int1.p7c').rename(www / 'int1.gone')
got = isemon._acme_sorted(leaf + int2, leaf_key)
ok('...and when it cannot be read, as it came - not refused', isemon._pem_list(got['chain']),
   [int2])
(www / 'int1.gone').rename(www / 'int1.p7c')

print('the web server asked from this machine')


def serve(chain_pem):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    cf, kf = work / ('srv%d.pem' % random.randint(0, 10 ** 9)), work / 'srv.key'
    cf.write_text(chain_pem)
    kf.write_text(leaf_key)
    ctx.load_cert_chain(str(cf), str(kf))
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    sock.listen(5)

    def run():
        while True:
            try:
                c, _ = sock.accept()
            except OSError:
                return
            try:
                t = ctx.wrap_socket(c, server_side=True)
                t.close()
            except (ssl.SSLError, OSError):
                c.close()
    threading.Thread(target=run, daemon=True).start()
    return sock


s1 = serve(leaf)
r = isemon.tls_self_check('monitor.example.test', s1.getsockname()[1])
ok('the certificate alone: refused, as a client without AIA refuses it', r['ok'], False)
ok('...and why', 'unable to get local issuer' in r['said'], True)
s2 = serve(leaf + int2 + int1)
r = isemon.tls_self_check('monitor.example.test', s2.getsockname()[1])
ok('the whole chain: good', r['ok'], True)
r = isemon.tls_self_check('monitor.example.test', 1)
ok('nothing listening: not known, not a failure', r['ok'], None)

print('the check after a change, by itself')
(state / 'web' / 'look.json').write_text(json.dumps({'at': time.time(), 'cert': {
    'pem': leaf, 'port': str(s1.getsockname()[1])}}))
for f in ('request.json', 'request.taken'):
    try:
        (state / 'web' / f).unlink()
    except FileNotFoundError:
        pass
(state / 'web' / 'status.json').write_text(json.dumps({'state': 'done', 'hash': 'a', 'at': 1}))
got = wr.selfcheck_due()
ok('the web server sends the certificate alone: a failure', got['ok'], False)
ev = store.db.execute("SELECT level, detail FROM events WHERE detail LIKE '%own check%' "
                      "ORDER BY id DESC").fetchone()
ok('...an event, a warning', ev and ev['level'], 'warn')
n = store.db.execute("SELECT COUNT(*) AS n FROM events WHERE detail LIKE '%own check%'"
                     ).fetchone()['n']
wr.selfcheck_due()
ok('...once: not again while nothing changed', store.db.execute(
    "SELECT COUNT(*) AS n FROM events WHERE detail LIKE '%own check%'").fetchone()['n'], n)
(state / 'web' / 'look.json').write_text(json.dumps({'at': time.time(), 'cert': {
    'pem': leaf + int2 + int1, 'port': str(s2.getsockname()[1])}}))
got = wr.selfcheck_due()
ok('the whole chain put in: good again', got['ok'], True)
ok('...and said so', store.db.execute("SELECT level FROM events WHERE detail LIKE '%own check%' "
                                      "ORDER BY id DESC").fetchone()['level'], 'info')
ok('the card shows the check', wr.tls_page(True)['selfcheck']['ok'], True)
ok('the card reads what nginx sends', wr.tls_page(True)['served_chain']['state'], 'complete')

print('a private CA: its root given by hand')
os.environ['ISEMON_CA_BUNDLE'] = str(work / 'empty.pem')
isemon._TLS_CHAIN_SEEN.clear()
wr.tls_do({'action': 'upload', 'pem': [leaf + int2 + int1 + leaf_key]}, 'admin')
page = wr.tls_page(True)
ok('no root the system trusts: incomplete', page['chain']['state'], 'incomplete')
got = wr.tls_do({'action': 'tls_chain'}, 'admin')
ok('...Complete the chain reads the root, and names it as a private one',
   (got['complete'], got['message'].startswith('it leads to Test Root R1, a root the system '
                                               'does not trust')), (False, True))
ok('...the card says it leads to a private root', wr.tls_page(True)['chain'].get(
    'private_root'), 'Test Root R1')
got = wr.tls_do({'action': 'tls_chain_add', 'text': root}, 'admin')
ok('the root given: complete, a private root', (got['complete'], got['message']),
   (True, 'complete - 3 certificates up to Test Root R1 - a private root: only clients that '
          'trust it take it'))
ok('...kept beside, never sent', (wr.tls_conf()['root'], wr.request()['tls']['chain']),
   (root, int2 + int1))
ok('...the card names it', wr.tls_page(True)['root_names'], ['Test Root R1'])
os.environ['ISEMON_CA_BUNDLE'] = str(work / 'bundle.pem')
isemon._TLS_CHAIN_SEEN.clear()

print('the helper names the TLS port')
sys.path.insert(0, str(ROOT / 'deploy'))
src = (ROOT / 'deploy' / 'isemon_web.py').read_text()
ok('cert_now reads listen ... ssl', "out['port'] = lm.group(1)" in src, True)

httpd.shutdown()
print('\n%d passed, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
