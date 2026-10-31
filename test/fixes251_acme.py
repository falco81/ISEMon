#!/usr/bin/env python3
"""1.10.251: Settings → Automatic certificates - the dashboard's certificate
ordered from an ACME CA and renewed by itself (after otp 1.0.169 - 1.0.187).

A fake ACME CA runs here, over HTTPS, speaking enough of RFC 8555 - the
directory, newNonce, newAccount, newOrder, the authorizations and their
challenges, finalize and the certificate - and checking every request's
ES256 signature with openssl. A real daemon answers the API on a port of its
own; the CA asks it for the HTTP-01 answer the way acme.php does.

What is checked:
  * off by default - an installation that never switches it on asks nothing
    of root, opens nothing in the firewall, orders nothing;
  * the settings checked, the secrets sealed;
  * a full HTTP-01 order end to end through the API, the certificate landing
    in web_tls exactly as an uploaded one does, the TLS settings kept;
  * /api/acme/challenge answers only a token an order waits on;
  * an account the CA no longer knows is made anew and the order asked again;
  * renewal at 30 days, or a third of the life of a short-lived certificate;
  * an uploaded certificate kept until Look after it, and Back to the one before;
  * DNS-01 by hand (the order waits for It is in DNS), RFC 2136 (the TSIG key
    in a 0600 file, never on the command line), deSEC (its name servers
    asked until both have the record);
  * root's helper: the location in the port-80 server, for everybody, bad
    names refused;
  * the firewall's own item for port 80;
  * no secret unsealed in the database, the events or the log.

    ./test/fixes251_acme.py
"""
import base64
import hashlib
import importlib.util
import io
import json
import os
import shutil
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

for k in list(os.environ):
    if k.lower() in ('http_proxy', 'https_proxy', 'all_proxy', 'no_proxy'):
        os.environ.pop(k)
os.environ.update({'ISEMON_WEB_HELPER': '0', 'ISEMON_ACME_SETTLE': '0.05',
                   'ISEMON_ACME_POLL': '0.2', 'ISEMON_ACME_DNS_LEAST': '0',
                   'ISEMON_ACME_SEEN_WAIT': '1', 'ISEMON_DESEC_SETTLE': '1'})

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
import isemon                                        # noqa: E402

PASS = FAIL = 0
PORT = 20300 + __import__("random").randint(0, 90)   # a range of its own: tests run side by side
NAME = 'isemon.example.net'
TSIG = 'c2VjcmV0LXRzaWcta2V5LTI1MC1kby1ub3Qtc2hvdw=='
DESEC_TOKEN = 'deSECtoken250abcdefghijKLMNOP'


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


def sh(args, data=None):
    return subprocess.run(args, input=data, capture_output=True)


def b64u(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def unb64u(text):
    return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))


work = Path(tempfile.mkdtemp(prefix='isemon-251-'))
os.chdir(str(work))

# ---- a test CA: a root, an issuing one, and the CA's own HTTPS certificate ----------
for args in (
        ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '30', '-subj', '/CN=Fake ACME Root',
         '-keyout', 'root.key', '-out', 'root.pem', '-addext', 'basicConstraints=critical,CA:TRUE',
         '-addext', 'keyUsage=critical,keyCertSign,cRLSign'],
        ['req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=Fake ACME Issuing',
         '-keyout', 'mid.key', '-out', 'mid.csr'],
        ['req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=127.0.0.1',
         '-keyout', 'srv.key', '-out', 'srv.csr']):
    assert sh(['openssl'] + args).returncode == 0, args
(work / 'ca.ext').write_text('basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n'
                             'subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n')
(work / 'srv.ext').write_text('subjectAltName=IP:127.0.0.1\nkeyUsage=critical,digitalSignature,'
                              'keyEncipherment\nextendedKeyUsage=serverAuth\n'
                              'subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n')
assert sh(['openssl', 'x509', '-req', '-in', 'mid.csr', '-CA', 'root.pem', '-CAkey', 'root.key',
           '-CAcreateserial', '-days', '30', '-extfile', 'ca.ext', '-out', 'mid.pem']).returncode == 0
assert sh(['openssl', 'x509', '-req', '-in', 'srv.csr', '-CA', 'root.pem', '-CAkey', 'root.key',
           '-CAcreateserial', '-days', '30', '-extfile', 'srv.ext', '-out', 'srv.pem']).returncode == 0
ROOT_PEM = (work / 'root.pem').read_text()


# ---- the fake ACME CA -------------------------------------------------------------------
class CA(object):
    port = 0
    accounts = {}           # id -> jwk
    nonces = set()
    orders = {}
    authz = {}
    certs = {}
    days = 90
    bad_nonce_once = False
    seen = []               # (path, kid or 'jwk')
    http_answers = []       # what the daemon gave for HTTP-01
    dns_txt = {}            # rr -> [txt]  (what "DNS" has)
    n = 0

    @classmethod
    def url(cls, path):
        return 'https://127.0.0.1:%d%s' % (cls.port, path)

    @classmethod
    def new_id(cls):
        cls.n += 1
        return str(cls.n)


def jwk_thumb(jwk):
    return b64u(hashlib.sha256(json.dumps({'crv': jwk['crv'], 'kty': jwk['kty'], 'x': jwk['x'],
                                           'y': jwk['y']}, separators=(',', ':'),
                                          sort_keys=True).encode()).digest())


def der_int(b):
    b = b.lstrip(b'\x00') or b'\x00'
    if b[0] & 0x80:
        b = b'\x00' + b
    return b'\x02' + bytes([len(b)]) + b


def es256_ok(jwk, signing_input, sig):
    if len(sig) != 64:
        return False
    body = der_int(sig[:32]) + der_int(sig[32:])
    der_sig = b'\x30' + bytes([len(body)]) + body
    spki = bytes.fromhex('3059301306072a8648ce3d020106082a8648ce3d030107034200') + b'\x04' + \
        unb64u(jwk['x']) + unb64u(jwk['y'])
    t = tempfile.mkdtemp(dir=str(work))
    (Path(t) / 'p.der').write_bytes(spki)
    (Path(t) / 's.der').write_bytes(der_sig)
    got = sh(['openssl', 'dgst', '-sha256', '-verify', str(Path(t) / 'p.der'), '-keyform', 'DER',
              '-signature', str(Path(t) / 's.der')], signing_input)
    shutil.rmtree(t, ignore_errors=True)
    return got.returncode == 0


class CAHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def nonce(self):
        n = b64u(os.urandom(12))
        CA.nonces.add(n)
        return n

    def answer(self, code, obj=None, headers=None, raw=None, kind='application/json'):
        data = raw if raw is not None else (json.dumps(obj).encode() if obj is not None else b'')
        self.send_response(code)
        self.send_header('Replay-Nonce', self.nonce())
        self.send_header('Content-Type', kind if raw is not None or code < 400 else
                         'application/problem+json')
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(data)

    def problem(self, kind, detail, code=400):
        self.answer(code, {'type': 'urn:ietf:params:acme:error:' + kind, 'detail': detail})

    def do_HEAD(self):
        if self.path == '/new-nonce':
            return self.answer(200)
        return self.answer(404)

    def do_GET(self):
        if self.path == '/directory':
            return self.answer(200, {'newNonce': CA.url('/new-nonce'), 'newAccount': CA.url('/new-acct'),
                                     'newOrder': CA.url('/new-order')})
        if self.path == '/new-nonce':
            return self.answer(204)
        self.problem('malformed', 'GET is only for the directory and nonces', 405)

    def do_POST(self):
        size = int(self.headers.get('Content-Length') or 0)
        if self.headers.get('Content-Type') != 'application/jose+json':
            return self.problem('malformed', 'not application/jose+json', 415)
        try:
            jws = json.loads(self.rfile.read(size))
            prot = json.loads(unb64u(jws['protected']))
            payload = json.loads(unb64u(jws['payload'])) if jws['payload'] else None
        except (ValueError, KeyError):
            return self.problem('malformed', 'not a JWS')
        if prot.get('alg') != 'ES256':
            return self.problem('badSignatureAlgorithm', 'ES256 only')
        if CA.bad_nonce_once:
            CA.bad_nonce_once = False
            return self.problem('badNonce', 'a nonce refused, once')
        if prot.get('nonce') not in CA.nonces:
            return self.problem('badNonce', 'unknown nonce')
        CA.nonces.discard(prot['nonce'])
        if prot.get('url') != CA.url(self.path):
            return self.problem('unauthorized', 'the url is not the one asked')
        if self.path == '/new-acct':
            jwk = prot.get('jwk')
            if not jwk or 'kid' in prot:
                return self.problem('malformed', 'newAccount wants a jwk')
            if not es256_ok(jwk, ('%s.%s' % (jws['protected'], jws['payload'])).encode(),
                            unb64u(jws['signature'])):
                return self.problem('unauthorized', 'bad signature')
            if not (payload or {}).get('termsOfServiceAgreed'):
                return self.problem('userActionRequired', 'agree to the terms')
            for aid, j in CA.accounts.items():
                if j == jwk:
                    return self.answer(200, {'status': 'valid'}, {'Location': CA.url('/acct/' + aid)})
            aid = CA.new_id()
            CA.accounts[aid] = jwk
            CA.seen.append(('new-acct', aid))
            return self.answer(201, {'status': 'valid', 'contact': payload.get('contact')},
                               {'Location': CA.url('/acct/' + aid)})
        kid = str(prot.get('kid') or '')
        aid = kid.rsplit('/', 1)[-1]
        if 'jwk' in prot or not kid.startswith(CA.url('/acct/')):
            return self.problem('malformed', 'a kid is wanted')
        if aid not in CA.accounts:
            return self.problem('accountDoesNotExist', 'no account %s' % aid)
        jwk = CA.accounts[aid]
        if not es256_ok(jwk, ('%s.%s' % (jws['protected'], jws['payload'])).encode(),
                        unb64u(jws['signature'])):
            return self.problem('unauthorized', 'bad signature')
        CA.seen.append((self.path.split('/')[1], aid))
        if self.path == '/new-order':
            oid = CA.new_id()
            names = [i['value'] for i in payload['identifiers']]
            azs = []
            for nm in names:
                zid = CA.new_id()
                CA.authz[zid] = {'status': 'pending', 'identifier': {'type': 'dns', 'value': nm},
                                 'acct': aid, 'challenges': [
                                     {'type': 'http-01', 'url': CA.url('/chal/%s/http' % zid),
                                      'token': b64u(os.urandom(24)), 'status': 'pending'},
                                     {'type': 'dns-01', 'url': CA.url('/chal/%s/dns' % zid),
                                      'token': b64u(os.urandom(24)), 'status': 'pending'}]}
                azs.append(CA.url('/authz/' + zid))
            CA.orders[oid] = {'status': 'pending', 'identifiers': payload['identifiers'],
                              'authorizations': azs, 'finalize': CA.url('/finalize/' + oid),
                              'acct': aid}
            return self.answer(201, CA.orders[oid], {'Location': CA.url('/order/' + oid)})
        parts = self.path.strip('/').split('/')
        if parts[0] == 'authz':
            z = CA.authz[parts[1]]
            return self.answer(200, {k: v for k, v in z.items() if k != 'acct'})
        if parts[0] == 'chal':
            z = CA.authz[parts[1]]
            ch = [c for c in z['challenges'] if c['type'] == parts[2] + '-01'][0]
            want = ch['token'] + '.' + jwk_thumb(CA.accounts[z['acct']])
            if parts[2] == 'http':
                # As the CA asks port 80: acme.php asks the daemon this.
                req = urllib.request.Request('http://127.0.0.1:%d/api/acme/challenge?token=%s'
                                             % (PORT, ch['token']))
                req.add_header('X-Isemon-Token', isemon.API_TOKEN)
                try:
                    with urllib.request.urlopen(req, timeout=10) as r:
                        got = json.loads(r.read().decode()).get('auth')
                except Exception as e:                  # noqa: BLE001
                    got = 'error %s' % e
                CA.http_answers.append(got)
                good = got == want
            else:
                txt = b64u(hashlib.sha256(want.encode()).digest())
                good = any(txt in v for v in CA.dns_txt.values())
            ch['status'] = 'valid' if good else 'invalid'
            if not good:
                ch['error'] = {'type': 'urn:ietf:params:acme:error:incorrectResponse',
                               'detail': 'the answer was not the one wanted'}
            z['status'] = 'valid' if good else 'invalid'
            return self.answer(200, ch)
        if parts[0] == 'finalize':
            o = CA.orders[parts[1]]
            if any(CA.authz[a.rsplit('/', 1)[-1]]['status'] != 'valid' for a in o['authorizations']):
                return self.problem('orderNotReady', 'not authorized')
            t = tempfile.mkdtemp(dir=str(work))
            (Path(t) / 'csr.der').write_bytes(unb64u(payload['csr']))
            r1 = sh(['openssl', 'req', '-inform', 'DER', '-in', str(Path(t) / 'csr.der'), '-out',
                     str(Path(t) / 'csr.pem')])
            text = sh(['openssl', 'req', '-in', str(Path(t) / 'csr.pem'), '-noout', '-text']).stdout.decode()
            if r1.returncode or ('DNS:' + o['identifiers'][0]['value']) not in text:
                return self.problem('badCSR', 'the CSR is not for the names ordered')
            CA.last_csr = text
            r2 = sh(['openssl', 'x509', '-req', '-in', str(Path(t) / 'csr.pem'), '-CA',
                     str(work / 'mid.pem'), '-CAkey', str(work / 'mid.key'), '-CAcreateserial',
                     '-days', str(CA.days), '-copy_extensions', 'copy', '-out',
                     str(Path(t) / 'leaf.pem')])
            if r2.returncode:
                return self.problem('serverInternal', r2.stderr.decode()[:200], 500)
            cid = CA.new_id()
            CA.certs[cid] = (Path(t) / 'leaf.pem').read_text() + (work / 'mid.pem').read_text()
            o.update(status='valid', certificate=CA.url('/cert/' + cid))
            return self.answer(200, o)
        if parts[0] == 'order':
            return self.answer(200, CA.orders[parts[1]])
        if parts[0] == 'cert':
            return self.answer(200, raw=CA.certs[parts[1]].encode(),
                               kind='application/pem-certificate-chain')
        self.problem('malformed', 'no such thing')


ca_srv = ThreadingHTTPServer(('127.0.0.1', 0), CAHandler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(str(work / 'srv.pem'), str(work / 'srv.key'))
ca_srv.socket = ctx.wrap_socket(ca_srv.socket, server_side=True)
CA.port = ca_srv.server_address[1]
threading.Thread(target=ca_srv.serve_forever, daemon=True).start()


# ---- a DNS server: what "DNS" has, for ACME's resolvers and deSEC's name servers -----
DNS_A = {'ns1.desec.io': '127.0.0.1', 'ns2.desec.org': '127.0.0.1', NAME: '127.0.0.1'}
DNS_ASKED = []


class DnsHandler(socketserver.BaseRequestHandler):
    def handle(self):
        import struct
        data, sock = self.request
        ident, _flags, qd = struct.unpack('>HHH', data[:6])
        at, labels = 12, []
        while data[at]:
            labels.append(data[at + 1:at + 1 + data[at]].decode())
            at += 1 + data[at]
        qname = '.'.join(labels).lower()
        qtype = struct.unpack('>H', data[at + 1:at + 3])[0]
        question = data[12:at + 5]
        DNS_ASKED.append((qname, qtype))
        answers = []
        if qtype == 1 and qname in DNS_A:
            answers.append((1, socket.inet_aton(DNS_A[qname])))
        if qtype == 16:
            for v in CA.dns_txt.get(qname, []):
                b = v.encode()
                answers.append((16, bytes([len(b)]) + b))
        out = struct.pack('>HHHHHH', ident, 0x8180, 1, len(answers), 0, 0) + question
        for t, rd in answers:
            out += b'\xc0\x0c' + struct.pack('>HHIH', t, 1, 60, len(rd)) + rd
        sock.sendto(out, self.client_address)


dns_srv = socketserver.ThreadingUDPServer(('127.0.0.1', 0), DnsHandler)
threading.Thread(target=dns_srv.serve_forever, daemon=True).start()
os.environ['ISEMON_ACME_DNS_PORT'] = str(dns_srv.server_address[1])


# ---- a fake deSEC API (plain HTTP on this machine) -------------------------------------
DESEC = {'rr': {}, 'calls': [], 'late': 2}


class DesecHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, code, obj):
        data = json.dumps(obj).encode() if obj is not None else b''
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        DESEC['calls'].append(('GET', self.path, self.headers.get('Authorization')))
        if self.headers.get('Authorization') != 'Token ' + DESEC_TOKEN:
            return self.reply(401, {'detail': 'bad token'})
        if self.path == '/api/v1/domains/acme.example.org/':
            return self.reply(200, {'name': 'acme.example.org', 'minimum_ttl': 3600})
        sub = self.path.split('/rrsets/')[-1].split('/')[0]
        recs = DESEC['rr'].get(sub)
        return self.reply(200, {'records': recs}) if recs else self.reply(404, {'detail': 'none'})

    def do_PATCH(self):
        body = json.loads(self.rfile.read(int(self.headers.get('Content-Length') or 0)))
        DESEC['calls'].append(('PATCH', self.path, body))
        for one in body:
            DESEC['rr'][one['subname']] = one['records']
            rr = '%s.acme.example.org' % one['subname']
            # deSEC's name servers have it only after a while.
            DESEC['late'] = 2
            DESEC['pending'] = (rr, [r.strip('"') for r in one['records']])
        return self.reply(200, body)


desec_srv = ThreadingHTTPServer(('127.0.0.1', 0), DesecHandler)
threading.Thread(target=desec_srv.serve_forever, daemon=True).start()
os.environ['ISEMON_DESEC_API'] = 'http://127.0.0.1:%d/api/v1' % desec_srv.server_address[1]


def desec_carry():
    """deSEC's name servers catching up: what was put there reaches "DNS"
    after a couple of questions."""
    while True:
        p = DESEC.get('pending')
        if p:
            asked = [q for q in DNS_ASKED if q[0] == p[0] and q[1] == 16]
            if len(asked) >= DESEC['late']:
                CA.dns_txt[p[0]] = p[1]
                DESEC['pending'] = None
        time.sleep(0.05)


threading.Thread(target=desec_carry, daemon=True).start()

# ---- the daemon ----------------------------------------------------------------------------
folder = work / 'state'
(folder / 'web').mkdir(parents=True)
isemon.STATE_DIR = folder
isemon.DB_FILE = folder / 'e.db'
isemon.BACKUP_DIR = folder / 'backups'
isemon.DUMP_DIR = folder / 'dumps'
isemon.RUN_DIR = folder
isemon.LOG_DIR = folder
isemon.CONFIG_FILE = folder / 'config.json'
isemon._LOG_PATH = folder / 'e.log'
isemon.TOKEN_FILE = folder / 'api-token'
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'api_port': PORT, 'geo': 0, 'ise_paths': [str(folder)]})
isemon.FILE_CONFIG.update({'api_port': PORT, 'geo': 0, 'ise_paths': [str(folder)]})
isemon.ACME_HOST.update(at=time.time(), fqdn='')       # no lookup of this machine's name
LOGS = []
_log = isemon.log


def _logged(msg, level='info'):
    LOGS.append(str(msg))
    return _log(msg, level)


isemon.log = _logged

store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)
daemon.add_user('boss', 'a-long-enough-password', 'fulladmin', by='test')
daemon.add_user('watcher', 'another-long-password', 'readonly', by='test')
api = isemon.ApiServer(daemon, PORT)
api.start()
time.sleep(0.4)
wr = daemon.webroot


def call(path, method='GET', payload=None, session=None, token=None):
    url = 'http://127.0.0.1:%d%s' % (PORT, path)
    body = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=body, method=method)
    if token is not False:
        req.add_header('X-Isemon-Token', token or isemon.API_TOKEN)
    if session:
        req.add_header('X-Isemon-Session', session)
    if body is not None:
        req.add_header('Content-Type', 'application/json')
    try:
        with urllib.request.urlopen(req, timeout=60) as answer:
            return answer.status, json.loads(answer.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except ValueError:
            return e.code, {}


def wait_order(session, most=60):
    end = time.time() + most
    v = {}
    while time.time() < end:
        _s, v = call('/api/acme', session=session)
        if not (v.get('work') or {}).get('busy'):
            return v
        time.sleep(0.2)
    return v


def events_text():
    return '\n'.join(r['detail'] for r in store.db.execute('SELECT detail FROM events'))


try:
    _s, d = call('/api/auth/login', 'POST', {'name': 'boss', 'password': 'a-long-enough-password'})
    admin = d['token']
    _s, d = call('/api/auth/login', 'POST', {'name': 'watcher', 'password': 'another-long-password'})
    looker = d['token']

    print('Off by default: nothing changes for an installation that never switches it on')
    ok('acme is off in DEFAULTS', isemon.DEFAULTS['acme'], 0)
    ok('nothing is asked of root', wr.request(), None)
    ok('the firewall has no item of ACME\'s', [i['key'] for i in wr.auto_rules({})].count('acme'), 0)
    isemon.ACME_WORK['at'] = 0.0
    isemon.acme_tick(daemon)
    ok('the hourly look orders nothing', (isemon.ACME_WORK['busy'], CA.seen), (False, []))
    ok('the Certificates and TLS page says ACME is off',
       wr.tls_page(True)['acme']['on'], False)

    print('\nWho may: a full administrator; the CA\'s question with nobody signed in')
    s, _ = call('/api/acme', session=looker)
    ok('a readonly account is refused the pane', s, 403)
    s, _ = call('/api/acme', 'POST', {'action': 'order'}, session=looker)
    ok('...and Order it now', s, 403)
    s, d = call('/api/acme', session=admin)
    ok('a full administrator sees it: off, the name not known yet', (s, d.get('on'), d.get('name')),
       (200, False, ''))
    s, d = call('/api/acme', 'POST', {'action': 'order'}, session=admin)
    ok('Order it now while off: refused, and said', (s, 'switch them on' in d.get('error', '')),
       (400, True))

    print('\nThe settings: checked, secrets sealed')
    for key, bad in (('acme_email', 'not a mail'), ('acme_url', 'http://ca.example/dir'),
                     ('acme_name', 'bad name;'), ('acme_dns_tsig_secret', 'not base64 !'),
                     ('acme_resolvers', '1.1.1.1, dns.example'), ('acme_dns_server', 'a b'),
                     ('acme_ca_pem', 'not a pem'), ('acme_days', 3)):
        try:
            daemon.save_settings({key: bad}, by='boss')
            ok('%s=%r refused' % (key, bad), False)
        except ValueError:
            ok('%s=%r refused' % (key, bad), True)
    daemon.save_settings({'acme_dns_tsig_secret': TSIG, 'acme_desec_token': DESEC_TOKEN}, by='boss')
    raw = {r['key']: r['value'] for r in store.db.execute('SELECT key, value FROM settings')}
    ok('the TSIG secret is sealed in the database',
       json.loads(raw['acme_dns_tsig_secret']).startswith('sealed:1:'))
    ok('...and the deSEC token', json.loads(raw['acme_desec_token']).startswith('sealed:1:'))
    ok('...and read back as they were', (isemon.CONFIG['acme_dns_tsig_secret'],
                                        isemon.CONFIG['acme_desec_token']), (TSIG, DESEC_TOKEN))
    st = {x['key']: x for x in daemon.settings_state()}
    ok('shown back masked', (st['acme_dns_tsig_secret']['secret'],
                             TSIG not in json.dumps(st['acme_dns_tsig_secret'])), (True, True))

    print('\nHTTP-01, end to end: switched on, ordered, put in as an uploaded one is')
    # The TLS settings of before - kept through ACME.
    wr.tls_do({'action': 'settings', 'preset': 'modern', 'hsts': 3600}, by='boss')
    daemon.save_settings({'acme': 1, 'acme_ca': 'custom', 'acme_url': CA.url('/directory'),
                          'acme_ca_pem': ROOT_PEM, 'acme_email': 'pki@example.net'}, by='boss')
    s, d = call('/api/acme', 'POST', {'action': 'name', 'name': NAME}, session=admin)
    ok('Its name… kept as acme_name', (s, d.get('name'), d.get('named'), isemon.CONFIG['acme_name']),
       (200, NAME, True, NAME))
    s, d = call('/api/acme', 'POST', {'action': 'name', 'name': 'not a name'}, session=admin)
    ok('...a name that is none refused', s, 400)
    # 1.10.258: what Try port 80 found under a key of its own - a port 80 that
    # does not answer is shown on the card, not taken for a refusal.
    s, d = call('/api/acme', 'POST', {'action': 'probe'}, session=admin)
    ok('Try port 80: an answer to show, whatever it found',
       (s, d.get('ok'), (d.get('probe') or {}).get('name'), 'said' in (d.get('probe') or {})),
       (200, True, NAME, True))
    ok('root is asked for port 80: the names in the request', wr.request().get('acme'), [NAME])
    ok('the care: ACME looks after a dashboard with no certificate of isemon\'s', isemon.acme_care(wr))
    CA.bad_nonce_once = True
    s, d = call('/api/acme', 'POST', {'action': 'order'}, session=admin)
    ok('Order it now: started', (s, 'being ordered' in d.get('message', '')), (200, True))
    v = wait_order(admin)
    st = v.get('state') or {}
    ok('the order went', (st.get('ok'), st.get('name'), st.get('said')), (True, NAME, None))
    ok('the CA got the right HTTP-01 answer from the daemon (as acme.php asks it)',
       len(CA.http_answers) == 1 and CA.http_answers[0] and '.' in CA.http_answers[0])
    ok('the challenge is gone from the database once the CA has looked',
       [r['key'] for r in store.db.execute("SELECT key FROM meta WHERE key LIKE 'acme:chal:%'")], [])
    words = [x[1] for x in st.get('steps')]
    ok('every step said, with its time', (words[0], 'the CA looks at http://%s/.well-known/'
                                         'acme-challenge/' % NAME in words, words[-1],
                                         all(isinstance(x[0], float) for x in st['steps'])),
       ('ordered from the CA', True, 'the certificate is put in', True))
    ok('...root\'s half not here: said, not waited for', any('root\'s half is not installed' in w
                                                         for w in words))
    ok('the request had the name alone', 'DNS:' + NAME in CA.last_csr and 'O = ' not in CA.last_csr)
    tls = wr.tls_conf()
    f = isemon.cert_facts(tls['cert'])
    ok('web_tls has it: how ACME, looked after, its key sealed',
       (tls.get('how'), tls.get('managed'), tls['key'].startswith('sealed:1:'), f['cn']),
       ('ACME', True, True, NAME))
    ok('the chain is the CA\'s issuing certificate',
       isemon.cert_facts(tls['chain'])['subject'].endswith('CN=Fake ACME Issuing'))
    ok('the TLS settings stay as they were', (tls.get('preset'), tls.get('hsts'), tls.get('protocols')),
       ('modern', 3600, ['TLSv1.3']))
    req = wr.request()
    ok('root is asked for it as for an uploaded one: the certificate and its key unsealed',
       (req['tls']['cert'] == tls['cert'], 'PRIVATE KEY' in req['tls']['key'],
        req['tls']['protocols']), (True, True, ['TLSv1.3']))
    ok('...the key the certificate\'s own',
       sh(['openssl', 'x509', '-noout', '-pubkey'], tls['cert'].encode()).stdout ==
       sh(['openssl', 'pkey', '-pubout'], req['tls']['key'].encode()).stdout)
    ok('an event says it came', 'a certificate for %s came from the CA' % NAME in events_text())
    acc = store.meta_json('acme:account', {})
    ok('the account kept: its key sealed, its kid, the mail', (
        acc['key'].startswith('sealed:1:'), acc['kid'].startswith(CA.url('/acct/')), acc['email']),
       (True, True, 'pki@example.net'))
    page = wr.tls_page(True)
    ok('Certificates and TLS: ACME renews it', (page['how'], page['acme']['on'], page['acme']['care']),
       ('ACME', True, True))
    ok('not due again: 90 days left', isemon.acme_due(wr, NAME), '')

    print('\nThe certificate lands in web_tls exactly as an uploaded one does')
    upload_keys = set(tls)
    snap = dict(tls)
    wr.tls_do({'action': 'upload', 'pem': [tls['chain'], tls['cert'],
                                            isemon.unseal_secret(tls['key'])]}, by='boss')
    up = wr.tls_conf()
    ok('the same fields', set(up), upload_keys)
    ok('the same values but how and when', {k: up[k] for k in up if k not in ('how', 'since', 'key')},
       {k: snap[k] for k in snap if k not in ('how', 'since', 'key')})
    ok('the upload said by hand: out of ACME\'s care, said in Events',
       (up['how'], isemon.acme_care(wr), 'ACME no longer renews the certificate' in events_text()),
       ('uploaded', False, True))
    wr._put('web_tls', snap)
    s, d = call('/api/acme', 'POST', {'action': 'care', 'on': True}, session=admin)
    ok('Look after it gives it back to ACME', (s, d.get('care')), (200, True))

    print('\n/api/acme/challenge answers only a token an order waits on')
    tok = 'Tok-' + 'a' * 30
    store.set_meta('acme:chal:' + tok, json.dumps({'auth': tok + '.thumb', 'at': time.time()}))
    s, d = call('/api/acme/challenge?token=' + tok)
    ok('a pending token: its answer, with nobody signed in', (s, d.get('auth')), (200, tok + '.thumb'))
    s, _ = call('/api/acme/challenge?token=' + 'b' * 30)
    ok('another token: 404', s, 404)
    s, _ = call('/api/acme/challenge?token=../../etc')
    ok('something that is no token: 404', s, 404)
    store.set_meta('acme:chal:' + tok, json.dumps({'auth': tok + '.thumb', 'at': time.time() - 7200}))
    s, _ = call('/api/acme/challenge?token=' + tok)
    ok('one older than an hour: 404', s, 404)
    s, _ = call('/api/acme/challenge?token=' + tok, token='wrong')
    ok('without the token of the pages: 401', s, 401)
    store.drop_meta('acme:chal:' + tok)
    php = (ROOT / 'web' / 'acme.php').read_text()
    ok('acme.php asks the daemon, the token only as it is in the path',
       "isemon_get('/api/acme/challenge?token=' . rawurlencode($m[1])" in php and
       '[A-Za-z0-9_-]{8,256}' in php)

    print('\nAn account the CA no longer knows is made anew, and the order asked again')
    old_kid = store.meta_json('acme:account', {})['kid']
    old_key = isemon.unseal_secret(store.meta_json('acme:account', {})['key'])
    CA.accounts.clear()
    s, d = call('/api/acme', 'POST', {'action': 'order'}, session=admin)
    v = wait_order(admin)
    acc = store.meta_json('acme:account', {})
    ok('the order went all the same', (v['state'].get('ok'), v['state'].get('said')), (True, None))
    ok('a new account, with a new key', (acc['kid'] != old_kid,
                                         isemon.unseal_secret(acc['key']) != old_key), (True, True))
    ok('said in the log', any('does not know the account any more' in x for x in LOGS))

    print('\nWhen it is renewed: 30 days left - or a third of the life of a short-lived one')
    real = isemon.cert_facts
    now = time.time()

    def facts(life, left):
        return lambda pem: dict(real(pem), **{'from': now - (life - left) * 86400,
                                               'until': now + left * 86400})
    for life, left, want in ((90, 60, ''), (90, 29.5, '29 days left'), (7, 6, ''), (7, 2.5, ''), (7, 2.2, '2 days left'),
                             (30, 11, ''), (30, 9.5, '9 days left')):
        isemon.cert_facts = facts(life, left)
        ok('%d days long, %s left: %r' % (life, left, want), isemon.acme_due(wr, NAME), want)
    isemon.cert_facts = facts(90, 10)
    store.set_meta('acme:state', json.dumps(dict(isemon.acme_state(store), failed_at=time.time() - 60)))
    ok('failed a minute ago: not again for 6 hours', isemon.acme_due(wr, NAME), '')
    isemon.cert_facts = real
    ok('another name: due at once', isemon.acme_due(wr, 'other.example.net'),
       'not ordered yet for other.example.net')
    CA.days = 7
    s, d = call('/api/acme', 'POST', {'action': 'order'}, session=admin)
    v = wait_order(admin)
    ok('a CA giving 7 days: ordered', (v['state'].get('ok'), round((v['not_after'] - time.time()) / 86400)),
       (True, 7))
    ok('...and not due again at once (otp 1.0.187: it was every hour)', isemon.acme_due(wr, NAME), '')
    CA.days = 90
    seen = len(CA.seen)
    isemon.ACME_WORK['at'] = 0.0
    isemon.acme_tick(daemon)
    time.sleep(0.3)
    ok('the hourly look orders nothing that is not due', (isemon.ACME_WORK['busy'], len(CA.seen)),
       (False, seen))

    print('\nAn uploaded certificate is kept until Look after it; Back to the one before')
    for args in (['req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=' + NAME,
                  '-keyout', 'own.key', '-out', 'own.csr'],):
        assert sh(['openssl'] + args).returncode == 0
    (work / 'own.ext').write_text('subjectAltName=DNS:%s\n' % NAME)
    assert sh(['openssl', 'x509', '-req', '-in', 'own.csr', '-CA', 'root.pem', '-CAkey', 'root.key',
               '-CAcreateserial', '-days', '200', '-extfile', 'own.ext', '-out', 'own.pem']).returncode == 0
    OWN = (work / 'own.pem').read_text()
    wr.tls_do({'action': 'upload', 'pem': [OWN, (work / 'own.key').read_text(), ROOT_PEM]}, by='boss')
    ok('put in by hand: ACME leaves it alone', isemon.acme_care(wr), False)
    seen = len(CA.seen)
    store.set_meta('acme:state', json.dumps({'name': NAME}))
    isemon.ACME_WORK['at'] = 0.0
    isemon.acme_tick(daemon)
    time.sleep(0.5)
    ok('the hourly look does not replace it', (len(CA.seen), wr.tls_conf()['cert']), (seen, OWN))
    s, d = call('/api/acme', 'POST', {'action': 'care', 'on': True}, session=admin)
    ok('Look after it', d.get('care'), True)
    isemon.ACME_WORK['at'] = 0.0
    isemon.acme_tick(daemon)
    time.sleep(0.2)
    v = wait_order(admin)
    ok('...and the next look orders it', (v['state'].get('ok'), v['how'], v['state'].get('by')),
       (True, 'ACME', 'isemon (renewal)'))
    b = v.get('before') or {}
    ok('the one it had is kept to go back to', (b.get('how'), b.get('ran_out'),
                                               'Fake ACME Root' in str(b.get('issuer'))),
       ('uploaded', False, True))
    ok('...its key as sealed as it was',
       store.meta_json('acme:before', {})['key'].startswith('sealed:1:'))
    s, d = call('/api/acme', 'POST', {'action': 'put_back'}, session=admin)
    tls = wr.tls_conf()
    ok('Back to the one before: the certificate and its key as they were',
       (s, tls['cert'], tls['how'], isemon.unseal_secret(tls['key']).strip() ==
        sh(['openssl', 'pkey', '-in', 'own.key']).stdout.decode().strip()), (200, OWN, 'uploaded', True))
    ok('...ACME leaves it alone, the TLS settings stay', (isemon.acme_care(wr), tls['preset']),
       (False, 'modern'))
    ok('...and nothing is kept from before any more', isemon.acme_before(wr), None)
    s, d = call('/api/acme', 'POST', {'action': 'put_back'}, session=admin)
    ok('...asked again: refused, and said', (s, 'no certificate from before' in d.get('error', '')),
       (400, True))
    daemon.save_settings({'acme': 0}, by='boss')
    wr.tls_do({'action': 'selfsigned', 'cn': NAME}, by='boss')
    ok('ACME off, a self-signed one made: taken over once ACME is switched on',
       (wr.tls_conf()['how'], isemon.acme_care(wr)), ('self-signed, made here', True))
    wr.tls_do({'action': 'upload', 'pem': [OWN, (work / 'own.key').read_text()]}, by='boss')
    ok('ACME off, one uploaded: kept when it is switched on', isemon.acme_care(wr), False)
    daemon.save_settings({'acme': 1}, by='boss')
    call('/api/acme', 'POST', {'action': 'care', 'on': True}, session=admin)

    print('\nDNS-01 by hand: the record shown, the order waiting for It is in DNS')
    daemon.save_settings({'acme_challenge': 'dns-01', 'acme_dns': 'manual', 'acme_dns_wait': 0},
                         by='boss')
    ok('no port 80 asked of root by DNS-01', 'acme' in (wr.request() or {}), False)
    ok('no item of ACME\'s in the firewall by DNS-01', [i['key'] for i in wr.auto_rules({})].count('acme'), 0)
    CA.dns_txt.clear()
    s, d = call('/api/acme', 'POST', {'action': 'order'}, session=admin)
    end = time.time() + 20
    while time.time() < end and not store.meta_json('acme:manual', None):
        time.sleep(0.1)
    time.sleep(0.4)
    _s, v = call('/api/acme', session=admin)
    m = v.get('manual') or {}
    ok('the record to put in is shown', (m.get('rr'), len(m.get('txt') or '')),
       ('_acme-challenge.' + NAME, 43))
    ok('what is waited for is said as it goes',
       'waiting for It is in DNS' in (v.get('work') or {}).get('says', ''))
    ok('In your DNS: by hand, at every order', [(r['type'], r['record']) for r in v['dns_guide']['rows']],
       [('TXT', '_acme-challenge.' + NAME)])
    CA.dns_txt['_acme-challenge.' + NAME] = [m['txt']]
    s, d = call('/api/acme', 'POST', {'action': 'manual_done'}, session=admin)
    v = wait_order(admin)
    ok('It is in DNS: the order goes on, and the certificate comes', (s, v['state'].get('ok')), (200, True))
    ok('nothing waits any more', v.get('manual'), None)
    s, d = call('/api/acme', 'POST', {'action': 'order'}, session=admin)
    end = time.time() + 20
    while time.time() < end and not store.meta_json('acme:manual', None):
        time.sleep(0.1)
    call('/api/acme', 'POST', {'action': 'manual_drop'}, session=admin)
    v = wait_order(admin)
    ok('Give the order up: the order fails, and says so', (v['state'].get('ok'),
                                                         'given up' in v['state'].get('said', '')),
       (False, True))

    print('\nDNS-01 by RFC 2136: the TSIG key in a 0600 file for the moment nsupdate runs')
    log = work / 'nsupdate.log'
    fake = work / 'nsupdate'
    fake.write_text('#!%s\nimport json, os, stat, sys\nk = sys.argv[sys.argv.index("-k") + 1]\n'
                    'st = os.stat(k)\nscript = sys.stdin.read()\n'
                    'open(%r, "a").write(json.dumps({"argv": sys.argv, "mode": oct(stat.S_IMODE(st.st_mode)), '
                    '"key": open(k).read(), "script": script, "keyfile": k}) + "\\n")\n'
                    'import re\nm = re.search(r\'update add (\\S+) 60 TXT "([^"]+)"\', script)\n'
                    'if m:\n    open(%r, "w").write(json.dumps([m.group(1), m.group(2)]))\n'
                    % (sys.executable, str(log), str(work / 'dns.json')))
    fake.chmod(0o755)
    isemon.NSUPDATE = str(fake)
    daemon.save_settings({'acme_dns': 'rfc2136', 'acme_dns_server': '127.0.0.1:5353',
                          'acme_dns_zone': 'example.net', 'acme_dns_tsig_name': 'isemon-acme.',
                          'acme_resolvers': '127.0.0.1'}, by='boss')

    def carry_nsupdate():
        end2 = time.time() + 30
        while time.time() < end2:
            if (work / 'dns.json').exists():
                rr, txt = json.loads((work / 'dns.json').read_text())
                CA.dns_txt[rr] = [txt]
                return
            time.sleep(0.05)
    CA.dns_txt.clear()
    threading.Thread(target=carry_nsupdate, daemon=True).start()
    s, d = call('/api/acme', 'POST', {'action': 'order'}, session=admin)
    v = wait_order(admin)
    ok('the order went', (v['state'].get('ok'), v['state'].get('said')), (True, None))
    runs = [json.loads(x) for x in log.read_text().splitlines()]
    ok('nsupdate ran twice: the record put in, then taken away',
       ['update add' in r['script'] for r in runs], [True, False])
    ok('...the server, the zone and the record as asked', runs[0]['script'].split('\n')[:3],
       ['server 127.0.0.1 5353', 'zone example.net',
        'update add _acme-challenge.%s 60 TXT "%s"' % (NAME, json.loads((work / 'dns.json').read_text())[1])])
    ok('the TSIG secret never on its command line', any(TSIG in ' '.join(r['argv']) for r in runs), False)
    ok('...but in a file only isemon reads (0600)', [r['mode'] for r in runs], ['0o600', '0o600'])
    ok('...holding the key', 'secret "%s"' % TSIG in runs[0]['key'] and 'hmac-sha256' in runs[0]['key'])
    ok('...gone once nsupdate is done', any(os.path.exists(r['keyfile']) for r in runs), False)
    ok('the record looked for at ACME\'s DNS servers before the CA is asked',
       any('_acme-challenge.%s TXT is seen by 127.0.0.1' % NAME == x[1] for x in v['state']['steps']))

    print('\nDNS-01 by deSEC: its own name servers asked until both have the record')
    daemon.save_settings({'acme_dns': 'desec', 'acme_desec_domain': 'acme.example.org'}, by='boss')
    _s, v = call('/api/acme', session=admin)
    rows = v['dns_guide']['rows']
    ok('In your DNS: the NS records of a domain of your own at deSEC, and the CNAME, once',
       [(r['type'], r['record'], r['value']) for r in rows],
       [('NS', 'acme.example.org', 'ns1.desec.io. ns2.desec.org.'),
        ('CNAME', '_acme-challenge.' + NAME, '_acme-challenge.isemon.acme.example.org.')])
    CA.dns_txt.clear()
    DNS_ASKED.clear()
    says = []
    stop = threading.Event()

    def watch():
        while not stop.is_set():
            w = isemon.ACME_WORK.get('says') or ''
            if w and (not says or says[-1] != w):
                says.append(w)
            time.sleep(0.05)
    threading.Thread(target=watch, daemon=True).start()
    s, d = call('/api/acme', 'POST', {'action': 'order'}, session=admin)
    v = wait_order(admin)
    stop.set()
    steps = [x[1] for x in v['state'].get('steps') or []]
    ok('the order went', (v['state'].get('ok'), v['state'].get('said')), (True, None))
    ok('the record went to deSEC with its token, its TTL at least deSEC\'s minimum',
       [(c[0], c[2][0]['subname'], c[2][0]['ttl']) for c in DESEC['calls'] if c[0] == 'PATCH'][:1],
       [('PATCH', '_acme-challenge.isemon', 3600)])
    ok('...and taken away again', [c[2][0]['records'] for c in DESEC['calls'] if c[0] == 'PATCH'][-1], [])
    ok('deSEC\'s name servers looked up', ('ns1.desec.io', 1) in DNS_ASKED and ('ns2.desec.org', 1) in DNS_ASKED)
    ok('...and asked for the record until both had it',
       any('TXT is on ns1.desec.io, ns2.desec.org after' in x for x in steps))
    ok('what was waited for was said as it went',
       any('waiting for deSEC\'s name servers to have the record' in x for x in says) and
       any('more for deSEC\'s other places of the world' in x for x in says))

    print('\nRoot\'s helper: the location in the port-80 server, for everybody; bad names refused')
    conf = work / 'isemon.conf'
    shutil.copy(str(ROOT / 'deploy' / 'nginx-isemon.conf'), str(conf))
    os.environ.update({'ISEMON_NGINX_CONF': str(conf), 'ISEMON_WEB_NO_SERVICES': '1',
                       'ISEMON_CERT_DIR': str(work / 'certs'), 'ISEMON_STATE': str(work / 'rootstate')})
    spec = importlib.util.spec_from_file_location('isemon_web', str(ROOT / 'deploy' / 'isemon_web.py'))
    iw = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(iw)
    ok('a request with the name: taken', iw.checked({'acme': [NAME]})['acme'], [NAME])
    ok('...without: nothing asked of port 80', iw.checked({})['acme'], None)
    for bad in (['bad;name.example'], ['two words.example'], 'isemon.example.net', [NAME] * 11,
                ['x' * 300 + '.example'], ['under_score.example'], [None]):
        try:
            iw.checked({'acme': bad})
            ok('refused: %r' % (bad if len(str(bad)) < 60 else str(bad)[:60]), False)
        except iw.Refused:
            ok('refused: %r' % (bad if len(str(bad)) < 60 else str(bad)[:60]), True)
    text = conf.read_text()
    new, said = iw.acme_into(text, [NAME])
    port80 = new[slice(*iw.http_block(new))]
    loc = port80.split('location ^~ /.well-known/acme-challenge/ {')[1].split('}')[0]
    ok('the location is in the port-80 server', '/.well-known/acme-challenge/' in port80)
    ok('...for everybody', 'allow all;' in loc and 'deny' not in loc)
    ok('...handed to acme.php by the HTTPS server\'s own PHP',
       ('fastcgi_pass   unix:/run/php-fpm/www.sock;' in loc,
        'fastcgi_param  SCRIPT_FILENAME /var/www/isemon/acme.php;' in loc, 'HTTPS on' in loc),
       (True, True, False))
    ok('...the redirect to HTTPS moved into location /',
       'location / {\n        return 301 https://$host$request_uri;\n    }' in port80 and
       '\n    return 301' not in port80.split('location / {')[0])
    ok('...the name in its server_name', 'server_name blacklistmt.example.loc %s;' % NAME in port80)
    ok('...the HTTPS server untouched', new[slice(*iw.server_block(new))], text[slice(*iw.server_block(text))])
    ok('...and said', said, 'nginx: port 80 answers the ACME CA (%s)' % NAME)
    ok('asked again: nothing changes', iw.acme_into(new, [NAME]), (new, ''))
    a = iw.access_checked({'dashboard': {'any': False, 'from': ['10.0.0.0/8']}})
    conf.write_text(text)
    iw.nginx_part({'tls': None, 'access': a, 'acme': [NAME], 'fw': None}, {})
    after = conf.read_text()
    https = after[slice(*iw.server_block(after))]
    p80 = after[slice(*iw.http_block(after))]
    ok('with the dashboard for 10.0.0.0/8 alone: the HTTPS server says so',
       'allow 10.0.0.0/8;' in https and 'deny  all;' in https)
    ok('...and the CA\'s location is still for everybody',
       'allow all;' in p80.split('acme-challenge/ {')[1].split('}')[0] and 'deny' not in p80)
    ok('the file nginx would read: braces in pairs', after.count('{'), after.count('}'))
    if shutil.which('nginx'):
        print('  (nginx is here, but it is not asked: no root)')

    print('\nThe firewall: port 80 let in by itself while HTTP-01 is used')
    daemon.save_settings({'acme_challenge': 'http-01'}, by='boss')
    acc_ = {'dashboard': {'any': False, 'from': ['10.0.0.0/8']}, 'banfeed': {'same': True},
            'health': {'same': True}}
    items = {i['key']: i for i in wr.auto_rules({}, access=acc_)}
    ok('the pages for 10.0.0.0/8 alone', {r['source'] for r in items['web']['rules']}, {'10.0.0.0/8'})
    ok('...and port 80 from anywhere for the CA, IPv4 and IPv6',
       sorted((r['family'], r['proto'], r['port'], r['source']) for r in items['acme']['rules']),
       [(4, 'tcp', '80', ''), (6, 'tcp', '80', '')])
    ok('a card of its own, on', (items['acme']['title'], items['acme']['on']),
       ('Automatic certificates (HTTP-01)', True))
    ok('it can be turned off like the others', 'acme' in isemon.WebRoot.AUTO)
    wr._put('web_fw', {'on': True, 'off': ['acme'], 'rules': []})
    ok('...and turned off it is not in the chain', any(
        r.get('note') == 'ACME (HTTP-01)' for r in wr.fw_lines(look={})), False)
    wr._put('web_fw', {'on': True, 'off': [], 'rules': []})
    ok('...on, it is', any(r.get('note') == 'ACME (HTTP-01)' for r in wr.fw_lines(look={})), True)

    print('\nThe command line: --acme, --acme-order')
    class A(object):
        json = True
        acme_order = 'this'
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = isemon.cmd_acme(A(), isemon.Palette(False), store)
    got = json.loads(buf.getvalue())
    ok('--acme --json: the pane\'s view', (rc, got.get('name'), got.get('on')), (0, NAME, True))
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = isemon.cmd_acme_order(A(), isemon.Palette(False), store)
    ok('--acme-order this: ordered and followed', (rc, json.loads(buf.getvalue())['state']['ok']), (0, True))
    A.acme_order = 'otp2'
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = isemon.cmd_acme_order(A(), isemon.Palette(False), store)
    ok('--acme-order of something else: refused', rc, 1)
    A.json = False
    A.acme_order = 'all'
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = isemon.cmd_acme(A(), isemon.Palette(False), store)
    ok('--acme in words', (rc, 'ACME renews it' in buf.getvalue()), (0, True))

    got = subprocess.run([sys.executable, str(ROOT / 'isemon.py'), '--help'], capture_output=True,
                         text=True)
    ok('--help has --acme and --acme-order', (got.returncode, '--acme ' in got.stdout,
                                             '--acme-order' in got.stdout), (0, True, True))

    print('\nThe console: Network, time and power → Automatic certificates')

    class Dry(isemon.Console):
        def __init__(self):
            super(Dry, self).__init__(isemon.Palette(False))
            self.ran, self.items, self.pick = [], None, 'show'

        def sub(self, title_, items):
            self.items = (title_, items)

        def choose(self, title_, options, words='', cur=0):
            return self.pick if self.pick in [o[0] for o in options] else None

        def confirm(self, *a, **k):
            return True

        def act(self, *args, **k):
            self.ran.append(('act',) + args)

        def show_live(self, *args, **k):
            self.ran.append(('live',) + args)

        def live(self, fn):
            return fn()
    dry = Dry()
    dry.m_machine()
    items = {it[1]: it for it in dry.items[1]}
    ok('an item of its own, numbered on', (items.get('Automatic certificates (ACME)') or ('',))[0], '9')
    items['Automatic certificates (ACME)'][2]()
    dry.pick = 'order'
    items['Automatic certificates (ACME)'][2]()
    ok('...how it stands, and Order it now followed', dry.ran,
       [('act', '--acme'), ('live', '--acme-order', 'this')])

    print('\nNo secret unsealed in the database, the events or the log')
    secrets_ = [TSIG, DESEC_TOKEN, isemon.unseal_secret(store.meta_json('acme:account', {})['key'])
                .split('\n')[1], isemon.unseal_secret(wr.tls_conf()['key']).split('\n')[1]]
    try:
        store.db.execute('PRAGMA wal_checkpoint(FULL)')
    except Exception:
        pass
    blob = b''
    for p in folder.iterdir():
        if p.is_file() and p.name.startswith('e.db'):
            blob += p.read_bytes()
    ok('the database files', [s_[:12] for s_ in secrets_ if s_.encode() in blob], [])
    ev = events_text()
    ok('the events', [s_[:12] for s_ in secrets_ if s_ in ev], [])
    logtext = '\n'.join(LOGS)
    ok('the log', [s_[:12] for s_ in secrets_ if s_ in logtext], [])
    ok('nothing of the work left behind', sorted(p.name for p in folder.iterdir()
                                                if p.name.startswith(('.isemon-acme', '.isemon-dns'))), [])
finally:
    try:
        api.stop()
    except Exception:
        pass
    ca_srv.shutdown()
    dns_srv.shutdown()
    desec_srv.shutdown()
    os.chdir('/')
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d passed, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
