#!/usr/bin/env python3
"""1.10.261: Automatic certificates as Let's Encrypt's integration guide has
them - the key choices, dual-cert (an ECDSA certificate beside the RSA one),
ARI (RFC 9773: the CA's renewal window), the hourly look at a minute of the
machine's own, and a User-Agent on every request to the CA.

A fake ACME CA runs here over HTTPS (as in fixes251_acme.py), checking every
request's signature (ES256, ES384, RS256) with openssl, and offering renewalInfo when asked
to. A real daemon answers the HTTP-01 question; root's helper is run on a
real copy of deploy/nginx-isemon.conf.

What is checked:
  * every acme_key choice orders a CSR with that key (type and size, read by
    openssl); the account key is never the certificate's key;
  * dual: two orders, both certificates in web_tls (key2 sealed, never
    plain in the database), request() carries both pairs; the second order
    failing keeps the first, and it is ordered by itself at the next look;
    dual switched off takes it away;
  * root's helper writes two pairs, and one again when the second goes;
    refuses an RSA certificate as the second; nginx -t saying no puts every
    file back;
  * ARI: the CertID, the window honoured (a moment inside it, kept), the
    window moved picks anew, `replaces` sent on renewal, no ARI or a failing
    one falls back to the days;
  * the User-Agent on every request the CA saw;
  * an upload, a self-signed one, Back to the one before: no ECDSA
    certificate left behind;
  * the look's own minute and the retry's jitter.

    ./test/fixes261_acme_keys.py
"""
import base64
import hashlib
import importlib.util
import json
import os
import random
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

for k in list(os.environ):
    if k.lower() in ('http_proxy', 'https_proxy', 'all_proxy', 'no_proxy'):
        os.environ.pop(k)
os.environ.update({'ISEMON_WEB_HELPER': '0', 'ISEMON_ACME_SETTLE': '0.05',
                   'ISEMON_ACME_POLL': '0.2'})

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
import isemon                                        # noqa: E402

PASS = FAIL = 0
PORT = 20500 + random.randint(0, 90)    # a range of its own: tests run side by side
NAME = 'isemon.example.net'


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


def sh(args, data=None, env=None):
    return subprocess.run(args, input=data, capture_output=True, env=env)


def b64u(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def unb64u(text):
    return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))


def rfc3339(ts):
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(ts))


work = Path(tempfile.mkdtemp(prefix='isemon-261-'))
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
(work / 'leaf.ext').write_text('basicConstraints=critical,CA:FALSE\nsubjectKeyIdentifier=hash\n'
                               'authorityKeyIdentifier=keyid\nextendedKeyUsage=serverAuth\n')
assert sh(['openssl', 'x509', '-req', '-in', 'mid.csr', '-CA', 'root.pem', '-CAkey', 'root.key',
           '-CAcreateserial', '-days', '30', '-extfile', 'ca.ext', '-out', 'mid.pem']).returncode == 0
assert sh(['openssl', 'x509', '-req', '-in', 'srv.csr', '-CA', 'root.pem', '-CAkey', 'root.key',
           '-CAcreateserial', '-days', '30', '-extfile', 'srv.ext', '-out', 'srv.pem']).returncode == 0
ROOT_PEM = (work / 'root.pem').read_text()


# ---- the fake ACME CA -------------------------------------------------------------------
class CA(object):
    port = 0
    accounts = {}
    nonces = set()
    orders = {}
    authz = {}
    certs = {}
    days = 90
    seen = []               # (path, account)
    agents = []             # (method, path, User-Agent) of every request
    new_orders = []         # the payloads of newOrder
    csrs = []               # openssl's text of every CSR finalized
    fail_ec = False         # finalize refuses an ECDSA key
    ari_on = False
    ari_status = 200
    window = None           # (start, end)
    ari_asked = []
    reject_replaces = 0
    algs = []
    n = 0

    @classmethod
    def url(cls, path):
        return 'https://127.0.0.1:%d%s' % (cls.port, path)

    @classmethod
    def new_id(cls):
        cls.n += 1
        return str(cls.n)


def jwk_thumb(jwk):
    need = ('e', 'kty', 'n') if jwk['kty'] == 'RSA' else ('crv', 'kty', 'x', 'y')
    return b64u(hashlib.sha256(json.dumps({k: jwk[k] for k in need}, separators=(',', ':'),
                                          sort_keys=True).encode()).digest())


def der_int(b):
    b = b.lstrip(b'\x00') or b'\x00'
    if b[0] & 0x80:
        b = b'\x00' + b
    return b'\x02' + der_len(len(b)) + b


def der_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b


def der(tag, body):
    return bytes([tag]) + der_len(len(body)) + body


def jws_ok(alg, jwk, signing_input, sig):
    """A JWS signature checked by openssl: ES256, ES384 or RS256."""
    if alg in ('ES256', 'ES384'):
        size = 32 if alg == 'ES256' else 48
        if len(sig) != 2 * size or jwk.get('crv') != ('P-256' if size == 32 else 'P-384'):
            return False
        body = der_int(sig[:size]) + der_int(sig[size:])
        der_sig = der(0x30, body)
        prefix = '3059301306072a8648ce3d020106082a8648ce3d030107034200' if size == 32 else \
            '3076301006072a8648ce3d020106052b81040022036200'
        spki = bytes.fromhex(prefix) + b'\x04' + unb64u(jwk['x']) + unb64u(jwk['y'])
        digest = '-sha256' if size == 32 else '-sha384'
    elif alg == 'RS256':
        if jwk.get('kty') != 'RSA':
            return False
        rsa = der(0x30, der_int(unb64u(jwk['n'])) + der_int(unb64u(jwk['e'])))
        spki = der(0x30, bytes.fromhex('300d06092a864886f70d0101010500') + der(0x03, b'\x00' + rsa))
        der_sig, digest = sig, '-sha256'
    else:
        return False
    t = tempfile.mkdtemp(dir=str(work))
    (Path(t) / 'p.der').write_bytes(spki)
    (Path(t) / 's.der').write_bytes(der_sig)
    got = sh(['openssl', 'dgst', digest, '-verify', str(Path(t) / 'p.der'), '-keyform', 'DER',
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
        if self.path != '/directory':
            # As Let's Encrypt: no nonce with the directory - newNonce is asked.
            self.send_header('Replay-Nonce', self.nonce())
        self.send_header('Content-Type', kind if raw is not None or code < 400 else
                         'application/problem+json')
        for k, v in (headers or {}).items():
            if isinstance(v, list):
                for one in v:
                    self.send_header(k, one)
            else:
                self.send_header(k, v)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(data)

    def problem(self, kind, detail, code=400):
        self.answer(code, {'type': 'urn:ietf:params:acme:error:' + kind, 'detail': detail})

    def agent(self):
        CA.agents.append((self.command, self.path.split('?')[0], self.headers.get('User-Agent')))

    def do_HEAD(self):
        self.agent()
        if self.path == '/new-nonce':
            return self.answer(200)
        return self.answer(404)

    def do_GET(self):
        self.agent()
        if self.path == '/directory':
            d = {'newNonce': CA.url('/new-nonce'), 'newAccount': CA.url('/new-acct'),
                 'newOrder': CA.url('/new-order')}
            if CA.ari_on:
                d['renewalInfo'] = CA.url('/renewal-info')
            return self.answer(200, d)
        if self.path == '/new-nonce':
            return self.answer(204)
        if self.path.startswith('/renewal-info/') and CA.ari_on:
            cid = self.path.split('/renewal-info/', 1)[1]
            CA.ari_asked.append(cid)
            if CA.ari_status != 200:
                return self.problem('serverInternal', 'not now', CA.ari_status)
            start, end = CA.window
            return self.answer(200, {'suggestedWindow': {'start': rfc3339(start), 'end': rfc3339(end)}},
                               {'Retry-After': '21600'})
        self.problem('malformed', 'GET is only for the directory, nonces and renewalInfo', 405)

    def do_POST(self):
        self.agent()
        size = int(self.headers.get('Content-Length') or 0)
        if self.headers.get('Content-Type') != 'application/jose+json':
            return self.problem('malformed', 'not application/jose+json', 415)
        try:
            jws = json.loads(self.rfile.read(size))
            prot = json.loads(unb64u(jws['protected']))
            payload = json.loads(unb64u(jws['payload'])) if jws['payload'] else None
        except (ValueError, KeyError):
            return self.problem('malformed', 'not a JWS')
        if prot.get('alg') not in ('ES256', 'ES384', 'RS256'):
            return self.problem('badSignatureAlgorithm', 'ES256, ES384 or RS256')
        CA.algs.append(prot['alg'])
        if prot.get('nonce') not in CA.nonces:
            return self.problem('badNonce', 'unknown nonce')
        CA.nonces.discard(prot['nonce'])
        if prot.get('url') != CA.url(self.path):
            return self.problem('unauthorized', 'the url is not the one asked')
        if self.path == '/new-acct':
            jwk = prot.get('jwk')
            if not jwk or not jws_ok(prot['alg'], jwk, ('%s.%s' % (jws['protected'], jws['payload'])).encode(),
                                       unb64u(jws['signature'])):
                return self.problem('unauthorized', 'bad signature')
            for aid, j in CA.accounts.items():
                if j == jwk:
                    return self.answer(200, {'status': 'valid'}, {'Location': CA.url('/acct/' + aid)})
            aid = CA.new_id()
            CA.accounts[aid] = jwk
            return self.answer(201, {'status': 'valid'}, {'Location': CA.url('/acct/' + aid)})
        kid = str(prot.get('kid') or '')
        aid = kid.rsplit('/', 1)[-1]
        if aid not in CA.accounts:
            return self.problem('accountDoesNotExist', 'no account %s' % aid)
        jwk = CA.accounts[aid]
        if not jws_ok(prot['alg'], jwk, ('%s.%s' % (jws['protected'], jws['payload'])).encode(),
                        unb64u(jws['signature'])):
            return self.problem('unauthorized', 'bad signature')
        CA.seen.append((self.path.split('/')[1], aid))
        if self.path == '/new-order':
            CA.new_orders.append(payload)
            if payload.get('replaces') and CA.reject_replaces:
                CA.reject_replaces -= 1
                return self.problem('alreadyReplaced', 'that one was replaced already', 409)
            oid = CA.new_id()
            azs = []
            for i in payload['identifiers']:
                # The name's authorization, valid already once one was:
                # as a CA keeps it for a while.
                known = [z for z, v in CA.authz.items() if v['identifier']['value'] == i['value']
                         and v['status'] == 'valid' and v['acct'] == aid]
                if known:
                    azs.append(CA.url('/authz/' + known[-1]))
                    continue
                zid = CA.new_id()
                CA.authz[zid] = {'status': 'pending', 'identifier': {'type': 'dns', 'value': i['value']},
                                 'acct': aid, 'challenges': [
                                     {'type': 'http-01', 'url': CA.url('/chal/%s/http' % zid),
                                      'token': b64u(os.urandom(24)), 'status': 'pending'}]}
                azs.append(CA.url('/authz/' + zid))
            CA.orders[oid] = {'status': 'pending', 'identifiers': payload['identifiers'],
                              'authorizations': azs, 'finalize': CA.url('/finalize/' + oid)}
            return self.answer(201, CA.orders[oid], {'Location': CA.url('/order/' + oid)})
        parts = self.path.strip('/').split('/')
        if parts[0] == 'authz':
            z = CA.authz[parts[1]]
            return self.answer(200, {k: v for k, v in z.items() if k != 'acct'})
        if parts[0] == 'chal':
            z = CA.authz[parts[1]]
            ch = z['challenges'][0]
            want = ch['token'] + '.' + jwk_thumb(CA.accounts[z['acct']])
            req = urllib.request.Request('http://127.0.0.1:%d/api/acme/challenge?token=%s'
                                         % (PORT, ch['token']))
            req.add_header('X-Isemon-Token', isemon.API_TOKEN)
            try:
                with urllib.request.urlopen(req, timeout=10) as r:
                    got = json.loads(r.read().decode()).get('auth')
            except Exception as e:                      # noqa: BLE001
                got = 'error %s' % e
            good = got == want
            ch['status'] = z['status'] = 'valid' if good else 'invalid'
            return self.answer(200, ch)
        if parts[0] == 'finalize':
            o = CA.orders[parts[1]]
            t = tempfile.mkdtemp(dir=str(work))
            (Path(t) / 'csr.der').write_bytes(unb64u(payload['csr']))
            sh(['openssl', 'req', '-inform', 'DER', '-in', str(Path(t) / 'csr.der'), '-out',
                str(Path(t) / 'csr.pem')])
            text = sh(['openssl', 'req', '-in', str(Path(t) / 'csr.pem'), '-noout', '-text']).stdout.decode()
            CA.csrs.append(text)
            if CA.fail_ec and 'id-ecPublicKey' in text:
                return self.problem('badCSR', 'no ECDSA today')
            r2 = sh(['openssl', 'x509', '-req', '-in', str(Path(t) / 'csr.pem'), '-CA',
                     str(work / 'mid.pem'), '-CAkey', str(work / 'mid.key'), '-CAcreateserial',
                     '-days', str(CA.days), '-copy_extensions', 'copy', '-extfile',
                     str(work / 'leaf.ext'), '-out', str(Path(t) / 'leaf.pem')])
            if r2.returncode:
                return self.problem('serverInternal', r2.stderr.decode()[:200], 500)
            cid = CA.new_id()
            CA.certs[cid] = (Path(t) / 'leaf.pem').read_text() + (work / 'mid.pem').read_text()
            o.update(status='valid', certificate=CA.url('/cert/' + cid))
            return self.answer(200, o)
        if parts[0] == 'order':
            return self.answer(200, CA.orders[parts[1]])
        if parts[0] == 'cert':
            # An alternate chain offered: the default one is the one kept.
            return self.answer(200, raw=CA.certs[parts[1]].encode(),
                               kind='application/pem-certificate-chain',
                               headers={'Link': ['<%s>;rel="alternate"' % CA.url('/cert/' + parts[1] + '/1'),
                                                 '<%s>;rel="index"' % CA.url('/directory')]})
        self.problem('malformed', 'no such thing')


ca_srv = ThreadingHTTPServer(('127.0.0.1', 0), CAHandler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(str(work / 'srv.pem'), str(work / 'srv.key'))
ca_srv.socket = ctx.wrap_socket(ca_srv.socket, server_side=True)
CA.port = ca_srv.server_address[1]
threading.Thread(target=ca_srv.serve_forever, daemon=True).start()

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
isemon.ACME_HOST.update(at=time.time(), fqdn='')

store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)
api = isemon.ApiServer(daemon, PORT)
api.start()
time.sleep(0.4)
wr = daemon.webroot


def pub_of_key(pem):
    return sh(['openssl', 'pkey', '-pubout'], pem.encode()).stdout.decode().strip()


def pub_of_cert(pem):
    return sh(['openssl', 'x509', '-noout', '-pubkey'], pem.encode()).stdout.decode().strip()


def account_pub():
    return pub_of_key(isemon.unseal_secret(store.meta_json('acme:account', {})['key']))


def order(only_second=False):
    return isemon.acme_order(wr, NAME, 'boss', only_second=only_second)


def wait_idle(most=60):
    end = time.time() + most
    time.sleep(0.3)
    while time.time() < end and (isemon.ACME_WORK['busy'] or isemon.ACME_LOOK['busy']):
        time.sleep(0.1)


def openssl_cert_id(pem):
    """The ARI CertID worked out the other way: openssl's own words."""
    text = sh(['openssl', 'x509', '-noout', '-ext', 'authorityKeyIdentifier'], pem.encode()).stdout.decode()
    hexed = [ln.strip() for ln in text.splitlines()[1:] if ln.strip()][0]
    hexed = hexed.replace('keyid:', '').replace(':', '').strip()
    serial = sh(['openssl', 'x509', '-noout', '-serial'], pem.encode()).stdout.decode().strip().split('=')[1]
    if len(serial) % 2:
        serial = '0' + serial
    sb = bytes.fromhex(serial)
    if sb[0] & 0x80:
        sb = b'\x00' + sb
    return b64u(bytes.fromhex(hexed)) + '.' + b64u(sb)


def tick():
    isemon.ACME_WORK['at'] = 0.0
    isemon.acme_tick(daemon)
    wait_idle()


try:
    print('The settings: the key choices of Let\'s Encrypt, as upsmon 4.1.6 has them')
    ok('the certificate: Both (RSA 2048 + ECDSA P-256) for anybody who never saved it',
       (isemon.DEFAULTS['acme_key'], isemon.ACME_CERT_KEYS['dual']), ('dual', ('rsa2048', 'ec256')))
    ok('..."ec" saved before stays ECDSA P-256 alone', isemon.ACME_CERT_KEYS['ec'], ('ec256',))
    ok('the account: ECDSA P-256 by default', isemon.DEFAULTS['acme_account_key'], 'ec')
    for key, bad in (('acme_key', 'rsa1024'), ('acme_key', 'ec521'), ('acme_account_key', 'dual'),
                     ('acme_account_key', 'rsa1024')):
        try:
            daemon.save_settings({key: bad}, by='boss')
            ok('%s=%r refused' % (key, bad), False)
        except ValueError:
            ok('%s=%r refused' % (key, bad), True)
    st = {x['key']: x for x in daemon.settings_state()}
    ok('the words of the choices, upsmon\'s', (st['acme_key'].get('choice_words'),
                                               st['acme_account_key'].get('choice_words')),
       ({'dual': 'Both: RSA 2048 + ECDSA P-256 (advised)', 'dual-strong': 'Both: RSA 4096 + ECDSA P-384',
         'ec': 'ECDSA P-256', 'ec384': 'ECDSA P-384', 'rsa2048': 'RSA 2048', 'rsa3072': 'RSA 3072',
         'rsa4096': 'RSA 4096'},
        {'ec': 'ECDSA P-256 (ES256)', 'ec384': 'ECDSA P-384 (ES384)', 'rsa2048': 'RSA 2048 (RS256)',
         'rsa3072': 'RSA 3072 (RS256)', 'rsa4096': 'RSA 4096 (RS256)'}))
    ok('...in that order', (st['acme_key'].get('choices'), st['acme_account_key'].get('choices')),
       (['dual', 'dual-strong', 'ec', 'ec384', 'rsa2048', 'rsa3072', 'rsa4096'],
        ['ec', 'ec384', 'rsa2048', 'rsa3072', 'rsa4096']))
    page = (ROOT / 'web' / 'index.php').read_text()
    ok('the page: both drawn with the others of the pane, asleep while ACME is off',
       ("'acme_key', 'acme_account_key', 'acme_challenge'" in page,
        "acme_account_key: ['acme', '1']" in page), (True, True))
    ok('...the keys shown as upsmon does: Keys, Key, beside the account',
       ("['Keys', d.keys || '', true]" in page, "(a second certificate beside it)" in page,
        "' \\u00b7 ' + d.account.key" in page), (True, True, True))
    ok('...What the last order did: the time one narrow column (upsmon 4.1.7)',
       '.acme-steps-done .si-row .mono{flex:0 0 56px;white-space:nowrap' in page)
    ok('tls_new_key makes P-384 as well', 'ASN1 OID: secp384r1' in sh(
        ['openssl', 'pkey', '-noout', '-text'], isemon.tls_new_key('ec384').encode()).stdout.decode())
    days = isemon.acme_days_for({'from': time.time(), 'until': time.time() + 90 * 86400})
    ok('a certificate of 90 days: renewed at 30 days left, as before', days, 30.0)

    daemon.save_settings({'acme': 1, 'acme_ca': 'custom', 'acme_url': CA.url('/directory'),
                          'acme_ca_pem': ROOT_PEM, 'acme_name': NAME, 'acme_key': 'ec'}, by='boss')

    print('\nEvery key choice: a CSR with that key, never the account\'s')
    want = {'rsa2048': ('rsaEncryption', 'Public-Key: (2048 bit)'),
            'rsa3072': ('rsaEncryption', 'Public-Key: (3072 bit)'),
            'rsa4096': ('rsaEncryption', 'Public-Key: (4096 bit)'),
            'ec': ('id-ecPublicKey', 'prime256v1'), 'ec384': ('id-ecPublicKey', 'secp384r1')}
    acct = None
    for choice, (alg, size) in want.items():
        daemon.save_settings({'acme_key': choice}, by='boss')
        st_ = order()
        csr = CA.csrs[-1]
        tls = wr.tls_conf()
        ok('%s: the CSR is %s, %s' % (choice, alg, size.split(': ')[-1]), (alg in csr, size in csr), (True, True))
        ok('%s: the certificate in web_tls has that key' % choice,
           isemon.cert_key_kind(tls['cert']), isemon.ACME_CERT_KEYS[choice][0])
        if acct is None:
            acct = account_pub()
        ok('%s: the account key is not the certificate\'s, and stays the same' % choice,
           (pub_of_cert(tls['cert']) != acct, account_pub() == acct), (True, True))
        ok('%s: no ECDSA certificate beside it (dual off)' % choice, 'cert2' in tls, False)
        ok('%s: the state says the key, and the steps which was made' % choice,
           (st_.get('keys'), st_['steps'][0][1]),
           (isemon.KEY_KIND_WORDS[isemon.ACME_CERT_KEYS[choice][0]],
            'the key: ' + isemon.KEY_KIND_WORDS[isemon.ACME_CERT_KEYS[choice][0]]))
    a = isemon.Acme(store)
    real_new_key = isemon.tls_new_key
    isemon.tls_new_key = lambda kind: a.key_pem
    try:
        a.csr([NAME], 'ec256')
        ok('a certificate key that came out as the account\'s: refused', False)
    except isemon.AcmeError as e:
        ok('a certificate key that came out as the account\'s: refused', 'account' in str(e))
    finally:
        isemon.tls_new_key = real_new_key
        a.close()
    try:
        isemon.Acme(store).csr([NAME], 'rsa1024')
        ok('a key that is not one of the choices: refused', False)
    except isemon.AcmeError:
        ok('a key that is not one of the choices: refused', True)
    ok('the chain the CA sent is the one kept (its alternate left alone)',
       (isemon.cert_facts(wr.tls_conf()['chain'])['subject'].endswith('CN=Fake ACME Issuing'),
        any('other chain' in x[1] and 'default one is kept' in x[1] for x in isemon.acme_state(store)['steps'])),
       (True, True))

    print('\nThe key of the account: ES256, ES384, RS256 - never a certificate\'s')
    want_text = {'ec': 'prime256v1', 'ec384': 'secp384r1', 'rsa2048': '(2048 bit',
                 'rsa3072': '(3072 bit', 'rsa4096': '(4096 bit'}
    for choice, alg in (('ec384', 'ES384'), ('rsa2048', 'RS256'), ('rsa3072', 'RS256'),
                        ('rsa4096', 'RS256'), ('ec', 'ES256')):
        was = store.meta_json('acme:account', {})
        daemon.save_settings({'acme_account_key': choice}, by='boss')
        n0 = len(CA.algs)
        st_ = order()
        acc = store.meta_json('acme:account', {})
        ok('%s: a new account, every request signed %s and taken by the CA' % (choice, alg),
           (st_.get('ok'), acc['kid'] != was['kid'], acc['kind'], set(CA.algs[n0:])),
           (True, True, choice, {alg}))
        ok('%s: its key that kind, never the certificate\'s' % choice,
           (want_text[choice] in sh(['openssl', 'pkey', '-noout', '-text'], isemon.unseal_secret(
               acc['key']).encode()).stdout.decode(),
            pub_of_cert(wr.tls_conf()['cert']) != account_pub()), (True, True))
        ok('%s: shown beside the account' % choice, isemon.acme_view(wr)['account']['key'],
           isemon.ACME_ACCOUNT_WORDS[choice])
    kid = store.meta_json('acme:account', {})['kid']
    order()
    ok('the same kind again: the same account', store.meta_json('acme:account', {})['kid'], kid)
    a = isemon.Acme(store)
    ok('an account kept before 1.10.261 (no kind) is ECDSA P-256', a.akind, 'ec')
    a.close()

    print('\nDual-cert: an RSA certificate, and an ECDSA one beside it')
    daemon.save_settings({'acme_key': 'dual'}, by='boss')
    n0 = len(CA.new_orders)
    st_ = order()
    ok('the steps say which keys were made', ([x[1] for x in st_['steps']][0],
                                              'a second certificate, with a ECDSA P-256 key' in
                                              [x[1] for x in st_['steps']]),
       ('the keys: RSA 2048 + ECDSA P-256', True))
    tls = wr.tls_conf()
    ok('two orders for the same name', [o['identifiers'] for o in CA.new_orders[n0:]],
       [[{'type': 'dns', 'value': NAME}]] * 2)
    ok('...the second one quick: the name\'s authorization valid already',
       [x[0] for x in CA.seen[-12:]].count('chal'), 0)
    ok('the RSA one as before, the ECDSA P-256 one as cert2',
       (isemon.cert_key_kind(tls['cert']), isemon.cert_key_kind(tls['cert2'])), ('rsa2048', 'ec256'))
    ok('...key2 sealed, the certificate\'s own',
       (tls['key2'].startswith('sealed:1:'),
        pub_of_key(isemon.unseal_secret(tls['key2'])) == pub_of_cert(tls['cert2'])), (True, True))
    ok('...its chain the CA\'s', isemon.cert_facts(tls['chain2'])['subject'].endswith('CN=Fake ACME Issuing'))
    ok('...the state says so', st_.get('second', {}).get('ok'), True)
    req = wr.request()['tls']
    ok('request() carries both pairs, the keys unsealed',
       (req['cert'] == tls['cert'], req['cert2'] == tls['cert2'], req['chain2'] == tls['chain2'],
        'PRIVATE KEY' in req['key2'], pub_of_key(req['key2']) == pub_of_cert(req['cert2'])),
       (True, True, True, True, True))
    v = isemon.acme_view(wr)
    ok('the card: Keys, as upsmon shows them', (v['keys'], (v.get('second') or {}).get('words')),
       ('RSA 2048 bit + EC 256 bit', 'ECDSA P-256'))
    page_ = wr.tls_page(True)
    ok('Certificates and TLS: Key, and the second certificate\'s', ((page_.get('kept') or {}).get('key'),
                                                                   (page_.get('kept2') or {}).get('key')),
       ('RSA 2048 bit', 'EC 256 bit'))
    ok('not due: both are new', (isemon.acme_due(wr, NAME), isemon.acme_due_second(wr, NAME)), ('', ''))
    daemon.save_settings({'acme_key': 'dual-strong'}, by='boss')
    ok('the other curve asked: the one beside it is due by itself',
       isemon.acme_due_second(wr, NAME), 'the certificate beside it is not ECDSA P-384')
    first = wr.tls_conf()['cert']
    n0 = len(CA.new_orders)
    tick()
    tls = wr.tls_conf()
    ok('the next look orders it alone: one order, the RSA one left as it is',
       (len(CA.new_orders) - n0, tls['cert'] == first, isemon.cert_key_kind(tls['cert2'])),
       (1, True, 'ec384'))
    blob = b''
    store.db.execute('PRAGMA wal_checkpoint(FULL)') if hasattr(store, 'db') else None
    for p in folder.iterdir():
        if p.is_file() and p.name.startswith('e.db'):
            blob += p.read_bytes()
    k2 = isemon.unseal_secret(tls['key2']).split('\n')[1]
    ok('key2 is never plain in the database', k2.encode() in blob, False)

    print('\nThe second order failing keeps the first')
    daemon.save_settings({'acme_key': 'dual'}, by='boss')
    CA.fail_ec = True
    wr._put('web_tls', isemon.tls_drop_second(wr.tls_conf()))
    st_ = order()
    tls = wr.tls_conf()
    ok('the RSA one put in, and the order counted as done', (st_.get('ok'), isemon.cert_key_kind(tls['cert'])),
       (True, 'rsa2048'))
    ok('...no ECDSA one, and said', ('cert2' in tls, st_['second']['ok'], 'no ECDSA today' in st_['second']['said']),
       (False, False, True))
    ok('...in Events too', 'but not the ECDSA P-256 one beside it' in '\n'.join(
        r['detail'] for r in store.db.execute('SELECT detail FROM events')))
    r = st_['second_retry_at'] - st_['second_failed_at']
    ok('...asked again after 6 h +-10 %', 0.9 * isemon.ACME_RETRY <= r <= 1.1 * isemon.ACME_RETRY)
    ok('...not before', isemon.acme_due_second(wr, NAME), '')
    s2 = isemon.acme_state(store)
    s2['second_retry_at'] = time.time() - 1
    store.set_meta('acme:state', json.dumps(s2))
    ok('...after it: due by itself', isemon.acme_due_second(wr, NAME), 'no ECDSA P-256 certificate beside it yet')
    CA.fail_ec = False
    first = wr.tls_conf()['cert']
    tick()
    tls = wr.tls_conf()
    ok('...and the next look orders it, beside the RSA one as it was',
       (isemon.cert_key_kind(tls.get('cert2') or ''), tls['cert'] == first,
        isemon.acme_state(store)['second']['ok'], 'second_failed_at' in isemon.acme_state(store)),
       ('ec256', True, True, False))
    CA.fail_ec = True
    old2 = tls['cert2']
    order()
    ok('a renewal whose second order fails keeps the ECDSA one it had while it is good',
       wr.tls_conf().get('cert2'), old2)
    CA.fail_ec = False

    print('\nOne key asked for again: the ECDSA one goes at once')
    first = wr.tls_conf()['cert']
    n0 = len(CA.new_orders)
    daemon.save_settings({'acme_key': 'rsa2048'}, by='boss')
    tick()
    tls = wr.tls_conf()
    ok('at the next minute\'s look: cert2, key2, chain2 gone, the RSA one as it was, nothing ordered',
       ([k for k in isemon.TLS_SECOND if k in tls], tls['cert'] == first, len(CA.new_orders) - n0),
       ([], True, 0))
    ok('...and request() has one pair', 'cert2' in wr.request()['tls'], False)

    print('\nRoot\'s helper: two pairs in nginx, and one again')
    daemon.save_settings({'acme_key': 'dual'}, by='boss')
    s2 = isemon.acme_state(store)
    s2.pop('second_retry_at', None)
    s2.pop('second_failed_at', None)
    store.set_meta('acme:state', json.dumps(s2))
    order()
    conf = work / 'isemon.conf'
    certs = work / 'certs'
    certs.mkdir()
    shutil.copy(str(ROOT / 'deploy' / 'nginx-isemon.conf'), str(conf))
    conf.write_text(conf.read_text().replace('/etc/nginx/certs', str(certs)))
    (work / 'rootstate').mkdir()
    os.environ.update({'ISEMON_NGINX_CONF': str(conf), 'ISEMON_WEB_NO_SERVICES': '1',
                       'ISEMON_CERT_DIR': str(certs), 'ISEMON_STATE': str(work / 'rootstate')})
    spec = importlib.util.spec_from_file_location('isemon_web', str(ROOT / 'deploy' / 'isemon_web.py'))
    iw = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(iw)
    req = wr.request()
    t = iw.tls_checked(req['tls'])
    ok('the second pair checked as the first', (bool(t['pem2']), t['pem2']['cert'].strip() == req['tls']['cert2'].strip()),
       (True, True))
    said, _dh = iw.nginx_part({'tls': t, 'access': None, 'acme': None, 'fw': None}, {})
    block = conf.read_text()
    block = block[slice(*iw.server_block(block))]
    lines = [ln.split()[0:2] for ln in block.split('\n') if ln.strip().startswith('ssl_certificate')]
    ok('two ssl_certificate and two ssl_certificate_key, RSA first, each with its key',
       lines, [['ssl_certificate', str(certs / 'isemon.pem;')], ['ssl_certificate_key', str(certs / 'isemon.key;')],
               ['ssl_certificate', str(certs / 'isemon-ecdsa.pem;')],
               ['ssl_certificate_key', str(certs / 'isemon-ecdsa.key;')]])
    ok('the ECDSA files: its certificate and chain, its key 0600',
       ((certs / 'isemon-ecdsa.pem').read_text() == t['pem2']['cert'] + t['pem2']['chain'],
        oct((certs / 'isemon-ecdsa.key').stat().st_mode & 0o777)), (True, '0o600'))
    ok('...and said', 'and the second one (ECDSA) beside it' in said)
    ok('the vhost: braces in pairs', block.count('{'), block.count('}'))
    two_text = conf.read_text()
    said, _dh = iw.nginx_part({'tls': t, 'access': None, 'acme': None, 'fw': None}, {})
    ok('asked again: the same file', conf.read_text(), two_text)
    t1 = dict(t, pem2=None)
    iw.nginx_part({'tls': t1, 'access': None, 'acme': None, 'fw': None}, {})
    block = conf.read_text()
    block = block[slice(*iw.server_block(block))]
    lines = [ln.split()[0] for ln in block.split('\n') if ln.strip().startswith('ssl_certificate')]
    ok('no second pair asked: exactly one left', lines, ['ssl_certificate', 'ssl_certificate_key'])
    ok('...and its files gone', ((certs / 'isemon-ecdsa.pem').exists(), (certs / 'isemon-ecdsa.key').exists()),
       (False, False))
    bad = dict(req['tls'], cert2=req['tls']['cert'], key2=req['tls']['key'], chain2=req['tls']['chain'])
    try:
        iw.tls_checked(bad)
        ok('an RSA certificate as the second pair: refused', False)
    except iw.Refused as e:
        ok('an RSA certificate as the second pair: refused', 'ECDSA' in str(e))
    bad = dict(req['tls'], key2=isemon.tls_new_key('ec256'))
    try:
        iw.tls_checked(bad)
        ok('a key that is not the second certificate\'s: refused', False)
    except iw.Refused as e:
        ok('a key that is not the second certificate\'s: refused', 'not the one' in str(e))
    bad = dict(req['tls'])
    bad.pop('cert')
    bad.pop('key')
    try:
        iw.tls_checked(bad)
        ok('a second pair without the first: refused', False)
    except iw.Refused:
        ok('a second pair without the first: refused', True)
    # nginx -t saying no: every file as it was.
    fake = work / 'bin'
    fake.mkdir()
    (fake / 'nginx').write_text('#!/bin/sh\necho "nginx: [emerg] no" >&2\nexit 1\n')
    (fake / 'systemctl').write_text('#!/bin/sh\nexit 0\n')
    (fake / 'restorecon').write_text('#!/bin/sh\nexit 0\n')
    for f in fake.iterdir():
        f.chmod(0o755)
    path_was = os.environ.get('PATH', '')
    os.environ['PATH'] = '%s:%s' % (fake, path_was)
    iw.NO_SERVICES = False

    def files():
        return {p.name: p.read_bytes() for p in certs.iterdir()}
    try:
        for start, ask, what in ((t1, t, 'one pair to two'), (t, t1, 'two pairs to one')):
            iw.NO_SERVICES = True
            iw.nginx_part({'tls': start, 'access': None, 'acme': None, 'fw': None}, {})
            iw.NO_SERVICES = False
            before_conf, before_files = conf.read_text(), files()
            try:
                iw.nginx_part({'tls': ask, 'access': None, 'acme': None, 'fw': None}, {})
                ok('nginx -t saying no (%s): refused' % what, False)
            except iw.Refused as e:
                ok('nginx -t saying no (%s): refused' % what, 'nginx does not take it' in str(e))
            ok('...the vhost as it was', conf.read_text(), before_conf)
            ok('...and every file (the ECDSA pair too) as it was', files(), before_files)
    finally:
        os.environ['PATH'] = path_was
        iw.NO_SERVICES = True

    print('\nARI: the CA\'s renewal window (RFC 9773)')
    tls = wr.tls_conf()
    cid = isemon.ari_cert_id(tls['cert'])
    ok('the CertID: the AKI\'s keyIdentifier and the serial, as openssl reads them',
       cid, openssl_cert_id(tls['cert']))
    ok('...of the ECDSA one too', isemon.ari_cert_id(tls['cert2']), openssl_cert_id(tls['cert2']))
    ok('...none for something that is not a certificate', (isemon.ari_cert_id('-----BEGIN CERTIFICATE-----\nAAAA\n'
                                                                   '-----END CERTIFICATE-----'),
                                                         isemon.ari_cert_id('')), ('', ''))
    ok('no renewalInfo: renewed by the days', (isemon.acme_renews(wr) or {}).get('how'), 'days')
    ok('...and no "replaces" was sent', [o.get('replaces') for o in CA.new_orders if o.get('replaces')], [])
    CA.ari_on = True
    now = time.time()
    CA.window = (now + 40 * 86400, now + 42 * 86400)
    n0 = len(CA.new_orders)
    old_cert, old_cert2 = tls['cert'], tls['cert2']
    store.set_meta('acme:state', json.dumps(dict(isemon.acme_state(store), name=NAME)))
    row = isemon.acme_ari_row(store)
    row['dir_at'] = 0           # a day on: the directory is asked again
    store.set_meta('acme:ari', json.dumps(row))
    tick()
    row = isemon.acme_ari_row(store)
    ok('the hourly look learns renewalInfo and asks the window', (bool(row.get('url')), row.get('id'), cid in CA.ari_asked),
       (True, cid, True))
    ok('...a moment picked inside it', CA.window[0] <= row['pick'] <= CA.window[1])
    ok('...not due before it (60 days left otherwise would not be either)', isemon.acme_due(wr, NAME), '')
    rn = isemon.acme_renews(wr)
    ok('...the card says when, by ARI', (rn['how'], rn['at']), ('ari', row['pick']))
    ok('...nothing ordered', len(CA.new_orders) - n0, 0)
    pick = row['pick']
    isemon.acme_ari_fetch(store, tls['cert'])
    ok('asked again, the same window: the same moment', isemon.acme_ari_row(store)['pick'], pick)
    CA.window = (now - 3600, now - 60)
    row = isemon.acme_ari_row(store)
    row['next'] = 0
    store.set_meta('acme:ari', json.dumps(row))
    tick()
    tls = wr.tls_conf()
    ok('the window moved to now: picked anew, due, and renewed', (tls['cert'] != old_cert,
                                                                  tls['cert2'] != old_cert2), (True, True))
    reps = [o.get('replaces') for o in CA.new_orders[n0:]]
    ok('"replaces" sent: the RSA one\'s CertID, then the ECDSA one\'s',
       reps, [cid, isemon.ari_cert_id(old_cert2)])
    CA.window = (time.time() + 30 * 86400, time.time() + 31 * 86400)
    row = isemon.acme_ari_row(store)
    row['next'] = 0
    store.set_meta('acme:ari', json.dumps(row))
    isemon.acme_ari_fetch(store, tls['cert'])
    ok('the new certificate\'s window', (isemon.acme_ari_row(store)['id'], isemon.acme_due(wr, NAME)),
       (isemon.ari_cert_id(tls['cert']), ''))
    CA.reject_replaces = 1
    n0 = len(CA.new_orders)
    daemon.save_settings({'acme_key': 'rsa2048'}, by='boss')
    st_ = order()
    ok('a CA that will not take "replaces": ordered again without it',
       (st_.get('ok'), [bool(o.get('replaces')) for o in CA.new_orders[n0:]]), (True, [True, False]))
    CA.ari_status = 500
    row = isemon.acme_ari_row(store)
    try:
        isemon.acme_ari_fetch(store, wr.tls_conf()['cert'])
        ok('renewalInfo failing: said', False)
    except isemon.AcmeError:
        ok('renewalInfo failing: said', True)
    row = isemon.acme_ari_row(store)
    row['checked'] = time.time() - 3 * 86400
    store.set_meta('acme:ari', json.dumps(row))
    ok('...and once its window is two days old, renewed by the days again',
       (isemon.acme_renews(wr) or {}).get('how'), 'days')
    CA.ari_status = 200

    print('\nThe User-Agent on every request the CA saw')
    agents = {a_ for _m, _p, a_ in CA.agents}
    ok('one, and the same: isemon/%s (ACME client; +https://github.com/falco81/ISEMon)' % isemon.__version__,
       agents, {'isemon/%s (ACME client; +https://github.com/falco81/ISEMon)' % isemon.__version__})
    kinds = {(m, p.split('/')[1]) for m, p, _a in CA.agents}
    ok('...the directory, a nonce, the POSTs, renewalInfo and the certificate among them',
       {('GET', 'directory'), ('HEAD', 'new-nonce'), ('POST', 'new-order'), ('GET', 'renewal-info'),
        ('POST', 'cert'), ('POST', 'finalize')} <= kinds)

    print('\nAnything else that puts a certificate in leaves no ECDSA one behind')
    daemon.save_settings({'acme_key': 'dual'}, by='boss')
    order()
    ok('(dual again)', 'cert2' in wr.tls_conf())
    wr.tls_do({'action': 'selfsigned', 'cn': NAME}, by='boss')
    ok('self-signed: no cert2, key2, chain2', [k for k in isemon.TLS_SECOND if k in wr.tls_conf()], [])
    ok('...nor in request()', 'cert2' in wr.request()['tls'], False)
    isemon.acme_care_set(wr, True, 'boss')
    order()
    ok('(dual again, the self-signed one kept to go back to)', ('cert2' in wr.tls_conf(), bool(isemon.acme_before(wr))),
       (True, True))
    isemon.acme_put_back(wr, 'boss')
    tls = wr.tls_conf()
    ok('Back to the one before: as it was, whole - no ECDSA one beside it',
       (tls['how'], [k for k in isemon.TLS_SECOND if k in tls]), ('self-signed, made here', []))
    isemon.acme_care_set(wr, True, 'boss')
    order()
    tls = wr.tls_conf()
    wr.tls_do({'action': 'upload', 'pem': [tls['chain'], tls['cert'], isemon.unseal_secret(tls['key'])]}, by='boss')
    ok('an upload: no cert2, key2, chain2', [k for k in isemon.TLS_SECOND if k in wr.tls_conf()], [])
    isemon.acme_care_set(wr, True, 'boss')
    order()
    wr.tls_do({'action': 'settings', 'preset': 'intermediate'}, by='boss')
    ok('the TLS settings changed: the ECDSA one stays', 'cert2' in wr.tls_conf())
    ok('...the cipher lists in force have ECDHE-ECDSA and ECDHE-RSA suites',
       all('ECDHE-ECDSA' in c and 'ECDHE-RSA' in c for c in (iw.CIPHERS_DEFAULT,
                                                            isemon.TLS_PRESETS['intermediate']['ciphers'])))
    wr.tls_do({'action': 'forget'}, by='boss')
    ok('Let go: nothing of it kept', [k for k in isemon.TLS_SECOND if k in wr.tls_conf()], [])

    print('\nThe hourly look at this machine\'s own minute; the retry with a jitter')
    off = isemon.acme_offset(store)
    ok('a moment of the hour of its own, kept', (0 <= off < 3600, isemon.acme_offset(store)), (True, off))
    base = 1800000000.0 - (1800000000.0 % 3600)
    isemon.ACME_WORK['at'] = base + off + 5
    ok('...the next look not before that moment an hour on',
       (isemon.acme_look_now(store, base + off + 3600 - 1), isemon.acme_look_now(store, base + off + 3600 + 1)),
       (False, True))
    isemon.ACME_WORK['at'] = 0.0
    ok('...and at once after a start or a change of the settings', isemon.acme_look_now(store), True)
    retries = []
    daemon.save_settings({'acme_url': CA.url('/nothing-here')}, by='boss')
    for _i in range(3):
        try:
            order()
        except isemon.AcmeError:
            pass
        s3 = isemon.acme_state(store)
        retries.append(s3['retry_at'] - s3['failed_at'])
    ok('a failure: retried after 6 h +-10 %', all(0.9 * isemon.ACME_RETRY <= r <= 1.1 * isemon.ACME_RETRY
                                                  for r in retries))
    ok('...not before', isemon.acme_due(wr, NAME), '')
finally:
    try:
        api.stop()
    except Exception:
        pass
    ca_srv.shutdown()
    os.chdir('/')
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d passed, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
