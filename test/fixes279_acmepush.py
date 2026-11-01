#!/usr/bin/env python3
"""1.10.279: acme push - the dashboard's certificate from acme (protocol 1).

acme (the certificate manager of ours) pushes and renews the dashboard's
certificate: Settings -> Certificates and TLS -> Certificates from acme.

- The primitives against the protocol's test vectors (section 8): Ed25519,
  X25519, HKDF-SHA256, AES-256-GCM, the pairing proof - by the cryptography
  module where it is installed, and in plain Python where it is not (both
  are run here).
- The receiver as acme speaks to it, through index.php and the daemon:
  hello; pairing by a code (wrong codes counted, five and it is gone; the
  confirmation checked as acme checks it); every refusal of the signature
  in its order (version, unsigned, unknown_key, stale, bad_signature,
  replay); inventory; install (the key opened, it is the certificate's, the
  names, a dual one, already there, force, other names, no slot, bad_key,
  key_mismatch, expired, not yet valid); forgetting the key.
- The certificate goes where an upload puts it, its key sealed, Automatic
  certificates leave it alone, and an event says so.

The sender is written here from the protocol's document alone.

    ./test/fixes279_acmepush.py
"""
import base64
import hashlib
import json
import os
import random
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
os.environ['ISEMON_WEB_HELPER'] = '1'
import isemon                                        # noqa: E402

PASS = FAIL = 0
PORT = 19700 + random.randint(0, 90)
WEB_PORT = PORT + 100
NAME = 'isemon.example.cz'


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


def b64(raw):
    return base64.b64encode(raw).decode()


# ---- the vectors of the document ------------------------------------------------
print('The primitives, against the document\'s vectors')
VEC_CODE = r'''
import base64, hashlib, hmac, sys
sys.path.insert(0, %r)
import isemon as E
b64 = lambda b: base64.b64encode(b).decode()
seed, app, eph, gn = bytes(range(32)), bytes(range(32, 64)), bytes(range(64, 96)), bytes(range(96, 108))
pub = E.push_ed25519_public(seed)
kid = E.push_key_id(pub)
APP = '00112233445566778899aabbccddeeff'
body = b'{"slots": ["auto"]}'
canon = E.push_canonical('inventory', APP, kid, '1793534400', 'n0nce-0123456789ab', body)
sig = E.push_ed25519_sign(seed, canon)
apub = E.push_x25519(app, E.PUSH_X25519_BASE)
epk = E.push_x25519(eph, E.PUSH_X25519_BASE)
sh = E.push_x25519(eph, apub)
k = E.push_hkdf_sha256(sh, epk + apub, b'acme-push/1 key_pem')
aad = ('acme-push/1 key\n%%s\n%%s' %% (APP, 'ab' * 32)).encode()
ct = E.push_aes256gcm(k, gn, b'KEY\n', aad, False)
try:
    E.push_aes256gcm(k, gn, ct, aad + b'x', True); bad = False
except ValueError:
    bad = True
rfc = E.push_x25519(bytes.fromhex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a'), E.PUSH_X25519_BASE).hex()
print('|'.join([b64(pub), kid, canon.decode().split(chr(10))[-1], b64(sig),
                str(E.push_ed25519_verify(pub, canon, sig)), str(E.push_ed25519_verify(pub, canon + b'x', sig)),
                b64(apub), b64(epk), sh.hex(), str(E.push_x25519(app, epk) == sh), k.hex(), b64(ct),
                str(E.push_aes256gcm(k, gn, ct, aad, True) == b'KEY\n'), str(bad),
                E.push_hmac('ABCD-EFGH-JKMN-PQRS', 'pair', APP, kid, 'n0nce-0123456789ab'), rfc,
                str(E.push_canonical('inventory', APP, kid, '1793534400', 'n0nce-0123456789ab', body)
                    == ('acme-push/1\ninventory\n' + APP + '\n' + kid + '\n1793534400\nn0nce-0123456789ab\n'
                        + 'd3a920a683e4d42e6f5a6971cb03c2fd4361964436db5f7460c4a638836222d8').encode())]))
''' % str(ROOT)
WANT = ['A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=', '56475aa75463474c',
        'd3a920a683e4d42e6f5a6971cb03c2fd4361964436db5f7460c4a638836222d8',
        '7nqJW4/NR3Et6pZx3B8qS3rvQGaQR0UTlNdptpRs4lxaZtc3Cf2zBRkOWPB0tV/rmQNfwbcl2/FKJ3Pu2h/bDg==',
        'True', 'False', 'NYBy1jZYgNGu6jKa35EhODhR7SGijjt16WXQ0s0WYlQ=',
        'eaYx7t4b+cmPEgMs3q3Q56B5OY/HhriMyEbsia+FpRo=',
        '04c304fb1ca83cee75e206344231f33797e07d9929db670994b7c6fbeb1dc255', 'True',
        '14067e8e830df01ae120ce73359b5f01e9d26931fe6ecdfa4d1a00fb9fe2e7b0',
        '2UbSrj9NwnCBu3qZW4U7MzxzlGw=', 'True', 'True',
        'e8e1978c03896460ce7f6e1697d5a5220c8f3a1cd8a01d2fc2e838dbd9318b39',
        '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a', 'True']
WORDS = ['acme\'s public key', 'its key id', 'SHA-256 of the body', 'the signature',
         'verified', 'a changed message refused', 'the application\'s public key', 'epk',
         'the shared secret', '...the same from the other side', 'the AES key', 'key.ct',
         'opened again', 'a changed aad refused', 'the pairing proof', 'RFC 7748 6.1',
         'the canonical string']
blocker = Path(tempfile.mkdtemp(prefix='isemon-279-nocrypto-'))
(blocker / 'cryptography').mkdir()
(blocker / 'cryptography' / '__init__.py').write_text('raise ImportError("not here")\n')
for label, env in (('the cryptography module', None),
                   ('plain Python (no cryptography module)', str(blocker))):
    e = dict(os.environ)
    if env:
        e['PYTHONPATH'] = env + os.pathsep + e.get('PYTHONPATH', '')
    r = subprocess.run([sys.executable, '-c', VEC_CODE], capture_output=True, text=True,
                       timeout=300, env=e)
    got = (r.stdout.strip().split('\n') or [''])[-1].split('|')
    if env:
        probe = subprocess.run([sys.executable, '-c', 'import cryptography'], env=e,
                               capture_output=True)
        ok('%s: cryptography is not to be had' % label, probe.returncode != 0)
    for w, a, b in zip(WORDS, got + [''] * 20, WANT):
        ok('%s: %s' % (label, w), a, b)
shutil.rmtree(str(blocker), ignore_errors=True)


# ---- a sender, from the document alone -------------------------------------------
class Acme(object):
    def __init__(self, base, name='acme 1.0.5 on acme1'):
        self.seed = os.urandom(32)
        self.pub = isemon.push_ed25519_public(self.seed)
        self.kid = hashlib.sha256(self.pub).hexdigest()[:16]
        self.text = 'acme-push-ed25519 %s acme@acme1' % b64(self.pub)
        self.base, self.name = base, name
        self.app_id = self.enc = None

    def get(self, op):
        try:
            with urllib.request.urlopen(self.base + '?api=acme-push-' + op, timeout=60) as a:
                return a.status, json.loads(a.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode() or '{}')

    def post(self, op, body, app_id=None, ts=None, nonce=None, key=None, kid=None, tamper=None,
             version='1', drop=None):
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        ts = str(int(time.time()) if ts is None else ts)
        nonce = nonce or secrets.token_hex(16)
        kid = kid or self.kid
        msg = '\n'.join(['acme-push/1', op, app_id or self.app_id, kid, ts, nonce,
                         hashlib.sha256(raw).hexdigest()]).encode()
        sig = isemon.push_ed25519_sign(key or self.seed, msg)
        head = {'X-Acme-Push-Version': version, 'X-Acme-Push-Key': kid,
                'X-Acme-Push-Time': ts, 'X-Acme-Push-Nonce': nonce,
                'X-Acme-Push-Signature': b64(sig)}
        if drop:
            head.pop(drop)
        req = urllib.request.Request(self.base + '?api=acme-push-' + op,
                                     data=tamper if tamper is not None else raw, method='POST')
        req.add_header('Content-Type', 'application/json')
        for k, v in head.items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=120) as a:
                return a.status, json.loads(a.read().decode()), nonce
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode() or '{}'), nonce

    def proof(self, code, words, *parts):
        return isemon.push_hmac(code, words, *parts)

    def seal(self, key_pem, fingerprint, enc=None, app_id=None):
        app_pub = base64.b64decode(enc or self.enc)
        eph = os.urandom(32)
        epk = isemon.push_x25519(eph, isemon.PUSH_X25519_BASE)
        shared = isemon.push_x25519(eph, app_pub)
        k = isemon.push_hkdf_sha256(shared, epk + app_pub, b'acme-push/1 key_pem')
        n = os.urandom(12)
        aad = ('acme-push/1 key\n%s\n%s' % (app_id or self.app_id, fingerprint.lower())).encode()
        return {'alg': 'X25519-HKDF-SHA256-A256GCM', 'epk': b64(epk), 'nonce': b64(n),
                'ct': b64(isemon.push_aes256gcm(k, n, key_pem.encode(), aad, False))}


def certificate(names, kind='ec', days=30, start=None):
    d = tempfile.mkdtemp(prefix='isemon-279-cert-')
    try:
        key = os.path.join(d, 'k')
        if kind == 'ec':
            subprocess.run(['openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt',
                            'ec_paramgen_curve:P-256', '-out', key], check=True,
                           capture_output=True)
        else:
            subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt',
                            'rsa_keygen_bits:2048', '-out', key], check=True, capture_output=True)
        san = ','.join('DNS:' + n for n in names)
        subprocess.run(['openssl', 'req', '-new', '-x509', '-key', key, '-days', str(days),
                        '-subj', '/CN=' + names[0], '-addext', 'subjectAltName=' + san,
                        '-out', os.path.join(d, 'c')], check=True, capture_output=True)
        cert, keypem = open(os.path.join(d, 'c')).read(), open(key).read()
        return cert, keypem, isemon.push_fingerprint(cert)
    finally:
        shutil.rmtree(d, ignore_errors=True)


work = Path(tempfile.mkdtemp(prefix='isemon-279-'))
php = None
api = None
try:
    state = work / 'state'
    state.mkdir()
    isemon.STATE_DIR = state
    isemon.DB_FILE = state / 'd.db'
    isemon.BACKUP_DIR = state / 'backups'
    isemon.DUMP_DIR = state / 'dumps'
    isemon.RUN_DIR = state
    isemon.LOG_DIR = state
    isemon.CONFIG_FILE = state / 'config.json'
    isemon._LOG_PATH = state / 'd.log'
    isemon.TOKEN_FILE = state / 'api-token'
    isemon.CONFIG.clear()
    isemon.CONFIG.update(isemon.DEFAULTS)
    isemon.CONFIG.update({'api_port': PORT, 'geo': 0, 'mikrotik1': 0, 'upgrade_check': 0,
                          'acme_name': NAME})
    (state / 'config.json').write_text(json.dumps({'db_engine': 'sqlite'}))
    store = isemon.Storage(isemon.DB_FILE)
    daemon = isemon.Daemon(store)
    daemon.add_user('boss', 'a-long-enough-password', 'fulladmin', by='test')
    daemon.add_user('watcher', 'a-third-long-password', 'readonly', by='test')
    api = isemon.ApiServer(daemon, PORT)
    api.start()
    time.sleep(0.4)
    isemon.TOKEN_FILE.write_text(isemon.API_TOKEN + '\n')
    web = work / 'web'
    shutil.copytree(str(ROOT / 'web'), str(web))
    lines = []
    for line in (web / 'isemon-api.php').read_text().split('\n'):
        if line.startswith('const ISEMON_PORT '):
            line = 'const ISEMON_PORT    = %d;' % PORT
        elif line.startswith('const ISEMON_TOKEN '):
            line = "const ISEMON_TOKEN   = '%s';" % isemon.TOKEN_FILE
        lines.append(line)
    (web / 'isemon-api.php').write_text('\n'.join(lines))
    if not shutil.which('php'):
        print('\n  --    no php here: the receiver is not tried through the page')
        raise SystemExit(0)
    php = subprocess.Popen(['php', '-S', '127.0.0.1:%d' % WEB_PORT, '-t', str(web)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.0)
    base = 'http://127.0.0.1:%d/index.php' % WEB_PORT
    acme = Acme(base)

    def admin(body=None, who='boss'):
        req = urllib.request.Request('http://127.0.0.1:%d/api/acme-push-admin' % PORT,
                                     data=json.dumps(body).encode() if body is not None else None,
                                     method='POST' if body is not None else 'GET')
        req.add_header('X-Isemon-Token', isemon.API_TOKEN)
        req.add_header('Content-Type', 'application/json')
        req.add_header('X-Isemon-Session', SESS[who])
        try:
            with urllib.request.urlopen(req, timeout=60) as a:
                return a.status, json.loads(a.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode() or '{}')

    def login(who, pw):
        req = urllib.request.Request('http://127.0.0.1:%d/api/auth/login' % PORT,
                                     data=json.dumps({'name': who, 'password': pw}).encode(),
                                     method='POST')
        req.add_header('X-Isemon-Token', isemon.API_TOKEN)
        req.add_header('Content-Type', 'application/json')
        with urllib.request.urlopen(req, timeout=60) as a:
            return json.loads(a.read().decode())['token']
    SESS = {'boss': login('boss', 'a-long-enough-password'),
            'watcher': login('watcher', 'a-third-long-password')}

    print('\nSwitched off (as it is, until somebody switches it on)')
    st, h = acme.get('hello')
    ok('hello says little: the app, its version, off', (st, h.get('app'), h.get('on'),
                                                       'app_id' in h, h.get('protocol')),
       (200, 'isemon', False, False, [1]))
    acme.app_id = '0' * 32
    st, r, _ = acme.post('inventory', {})
    ok('a signed request: off (403)', (st, r.get('code')), (403, 'off'))
    ok('a GET of pair: refused', acme.get('pair')[0], 405)
    ok('read only may look at the card, not switch it on',
       (admin(who='watcher')[0], admin({'action': 'on'}, 'watcher')[0]), (200, 403))

    print('\nSwitched on, nobody paired')
    st, d = admin({'action': 'on'})
    ok('on, its id and sealing key made', (st, d['on'], len(d.get('app_id') or ''),
                                          len(base64.b64decode(d.get('enc_key') or ''))),
       (200, True, 32, 32))
    box = json.loads(store.get_meta('acme_push:box'))
    ok('...the private half sealed in the database, not in clear',
       box['priv'].startswith(isemon.seal_secret('x')[:4]) and
       isemon.unseal_secret(box['priv']) is not None and
       base64.b64decode(isemon.unseal_secret(box['priv'])) not in json.dumps(box).encode())
    st, h = acme.get('hello')
    ok('hello: the id, the key, one slot of this machine, nobody paired, no code waiting',
       (h['on'], h['app_id'] == d['app_id'], h['enc_key'] == d['enc_key'], h['enc_alg'],
        h['slots'], h['paired'], h['pairing'], h['cluster']),
       (True, True, True, 'X25519-HKDF-SHA256-A256GCM', ['node:%s' % isemon.db_node_name()], 0,
        False, False))
    acme.app_id, acme.enc = h['app_id'], h['enc_key']
    st, r, _ = acme.post('inventory', {})
    ok('inventory before pairing: not_paired (401)', (st, r.get('code')), (401, 'not_paired'))
    pair_body = lambda n, code: {'acme_key': acme.text, 'acme_name': acme.name,  # noqa: E731
                                 'proof': acme.proof(code, 'pair', acme.app_id, acme.kid, n)}
    n = secrets.token_hex(16)
    st, r, _ = acme.post('pair', pair_body(n, 'ABCDEFGHJKMNPQRS'), nonce=n)
    ok('pair with no code waiting: pairing_closed (403)', (st, r.get('code')),
       (403, 'pairing_closed'))

    print('\nPairing by a code')
    st, d = admin({'action': 'pair'})
    code = d.get('code') or ''
    ok('a code, shown once: 16 letters as XXXX-XXXX-XXXX-XXXX', (st, len(code), code.count('-'),
                                                                  all(c in isemon.PUSH_CODE_ABC + '-'
                                                                      for c in code)),
       (200, 19, 3, True))
    ok('...not in clear in the database, nor on the card again',
       (code.replace('-', '') not in (store.get_meta('acme_push:pairing') or ''),
        'code' not in admin()[1]), (True, True))
    ok('hello says a code is waiting', acme.get('hello')[1]['pairing'], True)
    for i in range(4):
        n = secrets.token_hex(16)
        st, r, _ = acme.post('pair', pair_body(n, 'WRONGWRONGWRONG2'), nonce=n)
    ok('a wrong code: bad_code (403), counted', (st, r.get('code'),
                                                json.loads(store.get_meta('acme_push:pairing'))
                                                ['tries']), (403, 'bad_code', 4))
    n = secrets.token_hex(16)
    st, r, _ = acme.post('pair', pair_body(n, code), nonce=n, key=os.urandom(32))
    ok('the right code signed by another key than the body\'s: bad_signature, not paired',
       (st, r.get('code'), acme.get('hello')[1]['paired']), (401, 'bad_signature', 0))
    n = secrets.token_hex(16)
    st, r, _ = acme.post('pair', pair_body(n, 'WRONGWRONGWRONG2'), nonce=n)
    ok('the fifth wrong one: the code is gone', (st, store.get_meta('acme_push:pairing') or ''),
       (403, ''))
    n = secrets.token_hex(16)
    st, r, _ = acme.post('pair', pair_body(n, code), nonce=n)
    ok('...and the right one is too late: pairing_closed', r.get('code'), 'pairing_closed')
    code = admin({'action': 'pair'})[1]['code']
    n = secrets.token_hex(16)
    st, r, _ = acme.post('pair', pair_body(n, code), nonce=n)
    ok('a new code: paired', (st, r.get('ok'), r.get('app_id'), r.get('key_id'),
                              r.get('enc_key')), (200, True, acme.app_id, acme.kid, acme.enc))
    ok('...and its confirm is the code\'s, as acme checks it', r.get('confirm'),
       acme.proof(code, 'paired', acme.app_id, acme.kid, n, acme.enc))
    ok('...the code is gone after use', (store.get_meta('acme_push:pairing') or '',
                                          acme.get('hello')[1]['paired']), ('', 1))
    card = admin()[1]
    ok('the card: who is paired, by what', [(k['key_id'], k['name'], k['how'])
                                            for k in card['keys']],
       [(acme.kid, acme.name, 'pairing code')])

    print('\nThe signature, refused in its order')
    st, r, _ = acme.post('inventory', {}, version='2')
    ok('version 2: version (400)', (st, r.get('code')), (400, 'version'))
    st, r, _ = acme.post('inventory', {}, drop='X-Acme-Push-Signature')
    ok('no signature: unsigned (401)', (st, r.get('code')), (401, 'unsigned'))
    st, r, _ = acme.post('inventory', {}, nonce='short')
    ok('a nonce of the wrong shape: unsigned', r.get('code'), 'unsigned')
    other = os.urandom(32)
    st, r, _ = acme.post('inventory', {}, key=other,
                         kid=hashlib.sha256(isemon.push_ed25519_public(other)).hexdigest()[:16])
    ok('a key not paired here: unknown_key', (st, r.get('code')), (401, 'unknown_key'))
    st, r, _ = acme.post('inventory', {}, ts=int(time.time()) - 400)
    ok('400 s old: stale, and says by how much', (st, r.get('code'), '400 s' in r.get('error', '')
                                                  or '399 s' in r.get('error', '')
                                                  or '401 s' in r.get('error', '')),
       (401, 'stale', True))
    st, r, _ = acme.post('inventory', {}, tamper=b'{"x": 1}')
    ok('the body changed on the way: bad_signature', (st, r.get('code')), (401, 'bad_signature'))
    st, r, _ = acme.post('inventory', {}, app_id='f' * 32)
    ok('signed for another application: bad_signature', r.get('code'), 'bad_signature')
    nonce = secrets.token_hex(16)
    st1 = acme.post('inventory', {}, nonce=nonce)[0]
    st, r, _ = acme.post('inventory', {}, nonce=nonce)
    ok('the same nonce twice: replay', (st1, st, r.get('code')), (200, 401, 'replay'))
    st, r, _ = acme.post('inventory', b'[1, NaN]')
    ok('a body that is not a JSON object: bad_request', (st, r.get('code')), (400, 'bad_request'))
    big = b'{"x": "' + b'a' * (1 << 20) + b'"}'
    st, r, _ = acme.post('install', big)
    ok('over 1 MiB: too_big (413)', (st, r.get('code')), (413, 'too_big'))

    print('\nInventory')
    st, inv, _ = acme.post('inventory', {})
    slot = inv['slots'][0]
    ok('one slot, the dashboard of this machine, its name, nothing in it yet', (
        st, inv['app'], inv['app_id'], len(inv['slots']), slot['id'], slot['kind'],
        slot['names'], slot['current'], slot['managed_by'], slot['installable'], slot['dual'],
        inv['cluster']['on'], inv['other_names']),
       (200, 'isemon', acme.app_id, 1, 'node:%s' % isemon.db_node_name(), 'node', [NAME], None,
        'none', True, True, False, False))
    ok('inventory changes nothing', store.get_meta('web_tls') or '{}', '{}')

    print('\nInstall')
    cert, key, fp = certificate([NAME, 'www.' + NAME], 'ec')

    def push(c, k, f, **more):
        body = {'slots': ['auto'], 'cert_pem': c, 'chain_pem': '', 'fingerprint': f,
                'key': acme.seal(k, f), 'key_type': 'ec-256', 'names': [NAME],
                'not_after': 0, 'check_names': True, 'force': False}
        body.update(more)
        return acme.post('install', body)
    events_before = len(store.events(limit=500)[0])
    st, r, _ = push(cert, key, fp)
    ok('auto: put in for the dashboard, said', (st, r.get('ok'), [(x['slot'], x['state'],
                                                                    x['fingerprint'])
                                                                   for x in r.get('installed', [])]),
       (200, True, [('node:%s' % isemon.db_node_name(), 'installed', fp)]))
    tls = daemon.webroot.tls_conf()
    ok('...kept where an upload keeps it, as acme push, the key sealed and the certificate\'s',
       (isemon.push_fingerprint(tls['cert']), tls['how'], tls['managed'],
        isemon.key_pubkey(isemon.unseal_secret(tls['key']))[1] ==
        isemon.key_pubkey(key)[1], key.strip() not in json.dumps(tls)),
       (fp, 'acme push: %s' % acme.name, True, True, True))
    ok('...the TLS settings as an upload sets them', (tls['preset'], tls['hsts']),
       ('standard', 63072000))
    ok('...root asked to put it in (request.json)', (state / 'web' / 'request.json').exists())
    ok('...Automatic certificates leave it alone', isemon.acme_care(daemon.webroot), False)
    ok('...an event says which, until when, from which acme',
       any('acme push: a certificate for the dashboard' in (e['detail'] or '') and
           acme.name in e['detail'] for e in store.events(limit=20)[0]))
    ok('...nothing of the key in the log', key.split('\n')[1] not in
       (state / 'd.log').read_text() if (state / 'd.log').exists() else True)
    st, inv, _ = acme.post('inventory', {})
    ok('inventory: managed by acme push, its fingerprint', (inv['slots'][0]['managed_by'],
                                                            inv['slots'][0]['current']['fingerprint'],
                                                            inv['slots'][0]['current']['key_type']),
       ('acme-push', fp, 'ec-256'))
    since = tls['since']
    st, r, _ = push(cert, key, fp)
    ok('the same again: already, untouched', (r['installed'][0]['state'],
                                              daemon.webroot.tls_conf()['since']),
       ('already', since))
    st, r, _ = push(cert, key, fp, force=True)
    ok('...force: put in again', r['installed'][0]['state'], 'installed')
    st, r, _ = push(cert, key, fp, slots=['node:%s' % isemon.db_node_name()])
    ok('the slot by its id', (st, r['installed'][0]['slot']), (200, 'node:%s' % isemon.db_node_name()))
    st, r, _ = push(cert, key, fp, slots=['vip'])
    ok('a slot that is not here: no_slot (404)', (st, r.get('code')), (404, 'no_slot'))

    print('\nA dual one: ECDSA and RSA')
    rc, rk, rfp = certificate([NAME], 'rsa')
    ec2, ek2, efp2 = certificate([NAME], 'ec')
    st, r, _ = push(ec2, ek2, efp2, alt={'cert_pem': rc, 'chain_pem': '', 'fingerprint': rfp,
                                         'key': acme.seal(rk, rfp), 'key_type': 'rsa-2048'})
    tls = daemon.webroot.tls_conf()
    ok('both kept: RSA as the certificate, ECDSA beside it, tied to it',
       (st, isemon.push_fingerprint(tls['cert']), isemon.push_fingerprint(tls['cert2']),
        bool(isemon.tls_second(tls))), (200, rfp, efp2, True))
    st, inv, _ = acme.post('inventory', {})
    ok('inventory says the twin', (inv['slots'][0]['current'].get('alt') or {}).get('fingerprint'),
       efp2)
    st, r, _ = push(ec2, ek2, efp2, alt={'cert_pem': rc, 'chain_pem': '', 'fingerprint': rfp,
                                         'key': acme.seal(rk, rfp), 'key_type': 'rsa-2048'})
    ok('...the same pair again: already', r['installed'][0]['state'], 'already')
    st, r, _ = push(cert, key, fp, force=True)
    ok('one alone again: the twin goes', (st, daemon.webroot.tls_conf().get('cert2')), (200, None))
    st, r, _ = push(ec2, ek2, efp2, alt={'cert_pem': cert, 'chain_pem': '', 'fingerprint': fp,
                                         'key': acme.seal(key, fp), 'key_type': 'ec-256'})
    ok('a twin of the same key type: bad_request', (st, r.get('code')), (400, 'bad_request'))

    print('\nRefused')
    oc, okey, ofp = certificate(['other.example.org'], 'ec')
    st, r, _ = push(oc, okey, ofp)
    ok('another name, auto: names (422)', (st, r.get('code')), (422, 'names'))
    st, r, _ = push(oc, okey, ofp, slots=['this'])
    ok('another name, named slot: names (422)', (st, r.get('code')), (422, 'names'))
    st, r, _ = push(oc, okey, ofp, slots=['this'], check_names=False)
    ok('...check_names false while other names are not allowed: still names', r.get('code'),
       'names')
    st, r, _ = push(cert, key, 'ab' * 32)
    ok('a fingerprint that is not the certificate\'s: bad_request', (st, r.get('code')),
       (400, 'bad_request'))
    body_key = acme.seal(key, ofp)
    st, r, _ = push(cert, key, fp, key=body_key)
    ok('the key sealed for another certificate: bad_key', (st, r.get('code')), (400, 'bad_key'))
    st, r, _ = push(cert, key, fp, key=acme.seal(key, fp,
                                                enc=b64(isemon.push_x25519(os.urandom(32),
                                                                      isemon.PUSH_X25519_BASE))))
    ok('...sealed to another server\'s key: bad_key', r.get('code'), 'bad_key')
    st, r, _ = push(cert, okey, fp, key=acme.seal(okey, fp))
    ok('another certificate\'s key: key_mismatch (422)', (st, r.get('code')), (422, 'key_mismatch'))
    st, r, _ = push('nothing', key, fp)
    ok('no certificate at all: bad_cert', (st, r.get('code')), (422, 'bad_cert'))
    real_time = isemon.time

    class Clock(object):
        def __init__(self, at):
            self.at = at

        def __getattr__(self, name):
            return getattr(real_time, name)

        def time(self):
            return self.at
    box = isemon.push_box(store)
    for words, at, code_ in (('expired', time.time() + 60 * 86400, 'expired'),
                             ('not yet valid', time.time() - 86400, 'not_yet_valid')):
        isemon.time = Clock(at)
        try:
            isemon.push_one(box, {'cert_pem': cert, 'chain_pem': '', 'fingerprint': fp,
                                  'key': acme.seal(key, fp)})
            got = None
        except isemon.PushRefused as e:
            got = (e.status, e.code)
        finally:
            isemon.time = real_time
        ok('a certificate %s: %s (422)' % (words, code_), got, (422, code_))
    ok('the dashboard\'s certificate still the one put in', isemon.push_fingerprint(
        daemon.webroot.tls_conf()['cert']), fp)

    print('\nOther names, when allowed')
    admin({'action': 'other_names', 'on': True})
    st, r, _ = push(oc, okey, ofp, slots=['this'], check_names=False)
    ok('allowed and check_names false: taken', (st, r['installed'][0]['state']),
       (200, 'installed'))
    st, r, _ = push(oc, okey, ofp, slots=['this'])
    ok('...but not when acme asks for the names checked', (st, r.get('code')), (422, 'names'))
    admin({'action': 'other_names', 'on': False})
    push(cert, key, fp, force=True)

    print('\nEvery other way still there, with push on and paired (chapter 0)')
    wr = daemon.webroot
    ok('Certificates and TLS says how it came', wr.tls_page(True)['how'],
       'acme push: %s' % acme.name)
    ok('the install event names acme push and its key', any(
        ('by acme push, key %s' % acme.kid) in (e['detail'] or '')
        for e in store.events(limit=40)[0]))
    ok('...and the upload\'s own event, as by hand', any(
        'a certificate was put in for the dashboard' in (e['detail'] or '') and
        (e.get('who') or e.get('by') or 'acme push') == 'acme push'
        for e in store.events(limit=40)[0]))

    def slot_now():
        return acme.post('inventory', {})[1]['slots'][0]['managed_by']
    ok('inventory: acme-push', slot_now(), 'acme-push')
    uc, uk, ufp = certificate([NAME], 'rsa')
    got = wr.tls_do({'action': 'upload', 'pem': [uc, uk]}, by='boss')
    ok('an upload by hand: works as before and replaces it', (
        got['ok'], isemon.push_fingerprint(wr.tls_conf()['cert']), wr.tls_conf()['how'],
        slot_now()), (True, ufp, 'uploaded', 'manual'))
    got = wr.tls_do({'action': 'selfsigned', 'cn': NAME, 'key': 'ec256'}, by='boss')
    ok('a self-signed one: works as before', (got['ok'], wr.tls_conf()['how'], slot_now()),
       (True, 'self-signed, made here', 'manual'))
    got = wr.tls_do({'action': 'csr', 'cn': NAME, 'key': 'rsa2048'}, by='boss')
    ok('a request (CSR): works as before, the certificate left as it is',
       (got['ok'], '-----BEGIN CERTIFICATE REQUEST-----' in got['csr'],
        wr.tls_conf()['how']), (True, True, 'self-signed, made here'))
    wr.tls_do({'action': 'drop_request'}, by='boss')
    got = wr.tls_do({'action': 'settings', 'preset': 'modern', 'dh': 'none', 'hsts': 0},
                    by='boss')
    ok('the TLS settings: as before', (got['ok'], wr.tls_conf()['preset']), (True, 'modern'))
    push(cert, key, fp, force=True)
    ok('pushed again: the TLS settings stay as they were set',
       (wr.tls_conf()['preset'], wr.tls_conf()['hsts'], slot_now()), ('modern', 0, 'acme-push'))
    isemon.acme_care_set(wr, True, 'boss', 'Look after it')
    ok('Automatic certificates may take it back (Look after it)', isemon.acme_care(wr), True)
    ac, ak, afp = certificate([NAME], 'rsa')
    isemon.acme_install(wr, ac, ak, 'ACME')
    ok('...and its own certificate goes in as before: own-acme', (
        isemon.push_fingerprint(wr.tls_conf()['cert']), wr.tls_conf()['how'], slot_now()),
       (afp, 'ACME', 'own-acme'))
    push(cert, key, fp, force=True)
    ok('a push afterwards: as an upload, Automatic certificates leave it alone again',
       (slot_now(), isemon.acme_care(wr)), ('acme-push', False))

    print('\nPasted key, forgetting')
    acme2 = Acme(base, 'second')
    acme2.app_id, acme2.enc = acme.app_id, acme.enc
    st, d = admin({'action': 'paste', 'key': 'not a key'})
    ok('not a key: refused', st, 400)
    st, d = admin({'action': 'paste', 'key': acme2.text})
    ok('acme\'s key pasted: two acmes paired', (st, [k['how'] for k in d['keys']]),
       (200, ['pairing code', 'pasted']))
    st, r, _ = acme2.post('inventory', {})
    ok('...the second may ask', st, 200)
    st, d = admin({'action': 'forget', 'key_id': acme.kid})
    ok('the first forgotten', (st, [k['key_id'] for k in d['keys']]), (200, [acme2.kid]))
    st, r, _ = push(cert, key, fp, force=True)
    ok('...and refused from then on: unknown_key', (st, r.get('code')), (401, 'unknown_key'))
    st, d = admin({'action': 'off'})
    st, r, _ = acme2.post('inventory', {})
    ok('switched off: off, the certificate stays', (st, r.get('code'),
                                                    isemon.push_fingerprint(
                                                        daemon.webroot.tls_conf()['cert'])),
       (403, 'off', fp))
    ok('...and hello says only that', acme.get('hello')[1].get('app_id'), None)
    ok('events: on, the code, wrong codes, pairing, pasted, forgotten, off', all(
        any(w in (e['detail'] or '') for e in store.events(limit=200)[0]) for w in (
            'acme push: certificates are taken', 'a pairing code was made',
            'a wrong pairing code', 'acme push: paired with', 'was pasted', 'was forgotten',
            'no longer taken')))

    print('\nThe card\'s changes wait for the save bar (1.10.280)')
    acme3 = Acme(base, 'third')
    acme3.app_id, acme3.enc = acme.app_id, acme.enc
    st, d = admin({'action': 'save', 'on': True, 'other_names': True, 'add': ['junk'],
                   'forget': []})
    ok('one bad key in what is saved: refused, nothing of it saved',
       (st, isemon.push_conf(store)), (400, {'on': False, 'other_names': False}))
    st, d = admin({'action': 'save', 'on': True, 'other_names': True, 'add': [acme3.text],
                   'forget': [acme2.kid]})
    ok('saved at once: on, other names, a key taken, a key forgotten', (
        st, d['on'], d['other_names'], [k['key_id'] for k in d['keys']], d['message'][:6]),
       (200, True, True, [acme3.kid], 'saved:'))
    ok('...and the key taken may ask', acme3.post('inventory', {})[0], 200)
    st, d = admin({'action': 'save', 'on': None, 'other_names': None, 'add': [], 'forget': []})
    ok('nothing different: said so', (st, d['message']), (200, 'nothing was different'))
    st, d = admin({'action': 'save', 'forget': ['0123456789abcdef']})
    ok('a key to forget that is not here: refused', st, 400)
    st, d = admin({'action': 'save', 'on': False, 'add': [acme2.text]})
    ok('a key added while switching off: refused, nothing changed', (st, isemon.push_conf(store)['on']),
       (400, True))
    st, d = admin({'action': 'save', 'on': False, 'other_names': False}, who='watcher')
    ok('read only may not save', st, 403)
    st, d = admin({'action': 'save', 'on': False, 'other_names': False})
    ok('switched off by the save bar', (st, d['on'], d['other_names']), (200, False, False))

    print('\nThe page')
    page = (ROOT / 'web' / 'index.php').read_text()
    ok('acme\'s four requests before any session or same-page check', (
        page.index("if (preg_match('/^acme-push-(hello|pair|inventory|install)$/', $what, $pm))")
        < page.index('    if ($post) {\n        $told')), True)
    ok('...the body byte for byte, the five headers beside it', (
        "['body' => base64_encode($raw), 'headers' => $head]" in page,
        "foreach (['Version', 'Key', 'Time', 'Nonce', 'Signature'] as $h)" in page), (True, True))
    ok('the card on Certificates and TLS', ('id="tls-push-card"' in page,
                                            'function drawPush(d)' in page,
                                            "cmdButton('Pair with an acme'" in page,
                                            "'Or paste acme" in page,
                                            "'Take certificates of other names'" in page),
       (True,) * 5)
    ok('its changes wait for the save bar: kept as pending, saved at once, put back by Reset', (
        "extraPending('acme-push', {save: pushSave, reset: pushReset});" in page,
        "api('acme-push-admin', {action: 'save'," in page,
        "var sw = wrSwitch(on, function (v) { pushWant({on: v}); }, !may);" in page,
        "pushDo({action: 'off'})" not in page, "pushDo({action: 'forget'" not in page,
        "pushDo({action: 'paste'" not in page,
        "var SAVE_PANES = ['fw', 'time', 'about', 'tls'];" in page), (True,) * 7)
finally:
    if php:
        php.terminate()
        php.wait(timeout=10)
    if api is not None:
        try:
            api.stop()
        except Exception:
            pass
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
