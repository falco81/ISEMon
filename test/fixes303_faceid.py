#!/usr/bin/env python3
"""1.10.303: Face ID (passkeys, WebAuthn) as the second step of signing in.

Not a way in of its own: switched on, every sign-in with a password is half
of one until the person confirms it is them with a passkey - made the first
time (onboarding), used after that. A full admin sets somebody's Face ID up
again (their passkeys taken away: the next sign-in makes a new one). Here
through the daemon's own API, with an authenticator of the test's own:
keys made and signatures made by openssl, its CBOR written here.

    ./test/fixes303_faceid.py
"""
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import types
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import isemon                                        # noqa: E402

PASS = FAIL = 0
PORT = 19876
RP = 'isemon.example.cz'
ORIGIN = 'https://' + RP


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()


def unb64(t):
    return base64.urlsafe_b64decode(t + '=' * (-len(t) % 4))


def cbor(v):
    def head(major, n):
        if n < 24:
            return bytes([major << 5 | n])
        for info, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
            if n < 1 << (8 * size):
                return bytes([major << 5 | info]) + n.to_bytes(size, 'big')
    if isinstance(v, bool):
        return bytes([0xf5 if v else 0xf4])
    if isinstance(v, int):
        return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, bytes):
        return head(2, len(v)) + v
    if isinstance(v, str):
        raw = v.encode()
        return head(3, len(raw)) + raw
    if isinstance(v, list):
        return head(4, len(v)) + b''.join(cbor(x) for x in v)
    if isinstance(v, dict):
        return head(5, len(v)) + b''.join(cbor(k) + cbor(x) for k, x in v.items())
    raise TypeError(v)


def ossl(*args, data=None):
    return subprocess.run(['openssl'] + list(args), input=data, capture_output=True,
                          check=True).stdout


class Device(object):
    """An authenticator of the test's own: a P-256 key, Face ID always yes."""

    def __init__(self, folder):
        self.key = os.path.join(folder, 'dev-%d.pem' % id(self))
        ossl('ecparam', '-genkey', '-name', 'prime256v1', '-noout', '-out', self.key)
        der = ossl('ec', '-in', self.key, '-pubout', '-outform', 'DER')
        point = der[-65:]
        self.x, self.y = point[1:33], point[33:65]
        self.cid = os.urandom(16)
        self.count = 0

    def sign(self, data):
        return ossl('dgst', '-sha256', '-sign', self.key, data=data)

    def make(self, options, origin=ORIGIN, flags=0x45):
        cdj = json.dumps({'type': 'webauthn.create', 'challenge': options['challenge'],
                          'origin': origin}).encode()
        cose = cbor({1: 2, 3: -7, -1: 1, -2: self.x, -3: self.y})
        ad = (hashlib.sha256(options['rp']['id'].encode()).digest() + bytes([flags]) +
              (0).to_bytes(4, 'big') + bytes(16) + len(self.cid).to_bytes(2, 'big') +
              self.cid + cose)
        return {'clientDataJSON': b64(cdj),
                'attestationObject': b64(cbor({'fmt': 'none', 'attStmt': {}, 'authData': ad}))}

    def use(self, options, origin=ORIGIN, flags=0x05, count=None, bad=False):
        cdj = json.dumps({'type': 'webauthn.get', 'challenge': options['challenge'],
                          'origin': origin}).encode()
        self.count += 1
        ad = hashlib.sha256(options['rpId'].encode()).digest() + bytes([flags]) + \
            (self.count if count is None else count).to_bytes(4, 'big')
        sig = self.sign(ad + hashlib.sha256(cdj).digest())
        if bad:
            sig = self.sign(b'something else')
        return {'id': b64(self.cid), 'clientDataJSON': b64(cdj),
                'authenticatorData': b64(ad), 'signature': b64(sig)}


def call(path, method='GET', payload=None, session=None, host=RP, https=True):
    req = urllib.request.Request('http://127.0.0.1:%d%s' % (PORT, path),
                                 data=json.dumps(payload).encode() if payload is not None
                                 else None, method=method)
    req.add_header('X-Isemon-Token', isemon.API_TOKEN)
    req.add_header('X-Isemon-Host', host)
    req.add_header('X-Isemon-Https', '1' if https else '0')
    if session:
        req.add_header('X-Isemon-Session', session)
    if payload is not None:
        req.add_header('Content-Type', 'application/json')
    try:
        with urllib.request.urlopen(req, timeout=60) as answer:
            return answer.status, json.loads(answer.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or '{}')


def login(name='boss', password='a-long-enough-password'):
    status, d = call('/api/auth/login', 'POST', {'name': name, 'password': password})
    return d.get('token'), d.get('second')


folder = tempfile.mkdtemp(prefix='isemon-faceid-')
for k, v in dict(STATE_DIR=Path(folder), DB_FILE=Path(folder) / 'f.db',
                 BACKUP_DIR=Path(folder) / 'b', DUMP_DIR=Path(folder) / 'd', RUN_DIR=Path(folder),
                 LOG_DIR=Path(folder), CONFIG_FILE=Path(folder) / 'config.json',
                 _LOG_PATH=Path(folder) / 'f.log', TOKEN_FILE=Path(folder) / 'api-token').items():
    setattr(isemon, k, v)
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'api_port': PORT, 'geo': 0, 'mikrotik1': 0, 'ise_paths': [folder]})
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)
daemon.add_user('boss', 'a-long-enough-password', 'fulladmin', by='test')
daemon.add_user('watcher', 'another-long-password', 'readonly', by='test')
api = isemon.ApiServer(daemon, PORT)
api.start()
time.sleep(0.4)

try:
    print('Switched off, as it comes')
    ok('off as it comes', isemon.DEFAULTS['passkeys'], 0)
    tok, second = login()
    ok('a sign-in is whole with the password alone', second, '')
    ok('...the page answers it', call('/api/status', session=tok)[0], 200)
    ok('...and Face ID refuses', call('/api/auth/passkey', 'POST', {'step': 'begin',
                                                                     'want': 'enrol'},
                                      session=tok)[0], 403)
    st, d = call('/api/settings', 'POST', {'settings': {'passkeys': 1}}, session=tok,
                 host='10.0.0.5', https=False)
    ok('switched on from a page opened by an address: refused, and said why',
       (st, 'not switched on from this page' in d.get('error', '')), (409, True))
    st, d = call('/api/settings', 'POST', {'settings': {'passkeys': 1}}, session=tok)
    ok('...from one opened by name over https: switched on', (st, daemon.passkeys_on()),
       (200, True))
    ok('those signed in already stay signed in', call('/api/status', session=tok)[0], 200)

    print('\nThe first sign-in: Face ID set up (onboarding)')
    tok, second = login()
    ok('the password right: half a sign-in, Face ID to be set up', second, 'enrol')
    st, d = call('/api/auth/whoami', session=tok)
    ok('...the page is told', d['who']['second'], 'enrol')
    ok('...and nothing else answers it', call('/api/status', session=tok)[0], 403)
    ok('...not even what it chose for itself',
       call('/api/auth/prefs', 'POST', {'prefs': {'lang': 'cs'}}, session=tok)[0], 403)
    st, d = call('/api/auth/passkey', 'POST', {'step': 'begin', 'want': 'enrol'}, session=tok,
                 host='10.0.0.5')
    ok('by an address: no Face ID, and said so', (st, 'not by an address' in d.get('error', '')),
       (409, True))
    st, d = call('/api/auth/passkey', 'POST', {'step': 'begin', 'want': 'enrol'}, session=tok,
                 https=False)
    ok('over plain http: none either', st, 409)
    folder_dev = tempfile.mkdtemp(prefix='isemon-dev-')
    ipad = Device(folder_dev)
    st, d = call('/api/auth/passkey', 'POST', {'step': 'begin', 'want': 'enrol'}, session=tok)
    pk = d['publicKey']
    ok('the question: this name, Face ID required, no attestation',
       (pk['rp']['id'], pk['authenticatorSelection']['userVerification'], pk['attestation']),
       (RP, 'required', 'none'))
    st, d = call('/api/auth/passkey', 'POST', dict(ipad.make(pk, origin='https://evil.example'),
                                                    step='enrol'), session=tok)
    ok('answered from another page: refused', (st, 'another page' in d.get('error', '')),
       (403, True))
    st, d = call('/api/auth/passkey', 'POST', {'step': 'begin', 'want': 'enrol'}, session=tok)
    pk = d['publicKey']
    st, d = call('/api/auth/passkey', 'POST', dict(ipad.make(pk, flags=0x41), step='enrol'),
                 session=tok)
    ok('without Face ID itself (no UV): refused', (st, 'did not check that it is you'
                                                   in d.get('error', '')), (403, True))
    st, d = call('/api/auth/passkey', 'POST', {'step': 'begin', 'want': 'enrol'}, session=tok)
    pk = d['publicKey']
    made = ipad.make(pk)
    st, d = call('/api/auth/passkey', 'POST', dict(made, step='enrol', name='iPad'),
                 session=tok)
    ok('set up: the sign-in is whole', (st, d.get('done')), (200, True))
    ok('...the page answers it', call('/api/status', session=tok)[0], 200)
    st, d = call('/api/auth/passkey', 'POST', dict(made, step='enrol', name='iPad'),
                 session=tok)
    ok('the same answer twice: refused (a question is answered once)', st, 403)
    keys = store.passkeys('boss')
    ok('kept: the public half alone, for this name',
       (len(keys), keys[0]['host'], keys[0]['alg'], 'PRIVATE' in keys[0]['pem']),
       (1, RP, -7, False))

    print('\nEvery sign-in after it: Face ID used')
    tok, second = login()
    ok('the password right: Face ID still to come', second, 'verify')
    ok('...a new passkey cannot be made by half a sign-in',
       call('/api/auth/passkey', 'POST', {'step': 'begin', 'want': 'enrol'}, session=tok)[0], 403)
    st, d = call('/api/auth/passkey', 'POST', {'step': 'begin', 'want': 'check'}, session=tok)
    pk = d['publicKey']
    ok('the question names this account\'s passkeys alone',
       [c['id'] for c in pk['allowCredentials']], [b64(ipad.cid)])
    st, d = call('/api/auth/passkey', 'POST', dict(ipad.use(pk, bad=True), step='check'),
                 session=tok)
    ok('a signature that is not right: refused', (st, 'signature' in d.get('error', '')),
       (403, True))
    st, d = call('/api/auth/passkey', 'POST', {'step': 'begin', 'want': 'check'}, session=tok)
    pk = d['publicKey']
    st, d = call('/api/auth/passkey', 'POST', dict(ipad.use(pk), step='check'), session=tok)
    ok('the right one: the sign-in is whole', (st, d.get('done')), (200, True))
    ok('...and the page answers it', call('/api/status', session=tok)[0], 200)
    ok('...its use written down', bool(store.passkeys('boss')[0]['last_used']))
    tok, second = login()
    st, d = call('/api/auth/passkey', 'POST', {'step': 'begin', 'want': 'check'}, session=tok)
    st, d = call('/api/auth/passkey', 'POST', dict(ipad.use(d['publicKey'], count=1),
                                                    step='check'), session=tok)
    ok('a counter that went back: refused, it may have been copied',
       (st, 'counter went back' in d.get('error', '')), (403, True))
    for i in range(6):
        st, d = call('/api/auth/passkey', 'POST', {'step': 'begin', 'want': 'check'},
                     session=tok)
        if st != 200:
            break
        st, d = call('/api/auth/passkey', 'POST', dict(ipad.use(d['publicKey'], bad=True),
                                                        step='check'), session=tok)
        if st == 401:
            break
    ok('refused five times: the half sign-in ended', st, 401)

    print('\nA full admin sets it up again')
    w_tok, second = login('watcher', 'another-long-password')
    ok('somebody else\'s first sign-in: onboarding too', second, 'enrol')
    phone = Device(folder_dev)
    st, d = call('/api/auth/passkey', 'POST', {'step': 'begin', 'want': 'enrol'}, session=w_tok)
    call('/api/auth/passkey', 'POST', dict(phone.make(d['publicKey']), step='enrol',
                                           name='iPhone'), session=w_tok)
    ok('...set up', len(store.passkeys('watcher')), 1)
    st, d = call('/api/auth/passkeys', 'POST', {'do': 'reset', 'name': 'boss'}, session=w_tok)
    ok('a read-only account may not set anybody\'s up again', st, 403)
    tok, second = login()
    st, d = call('/api/auth/passkey', 'POST', {'step': 'begin', 'want': 'check'}, session=tok)
    call('/api/auth/passkey', 'POST', dict(ipad.use(d['publicKey']), step='check'), session=tok)
    st, d = call('/api/auth/users' if False else '/api/users', session=tok)
    ok('the accounts list says who has how many', d.get('passkeys'), {'boss': 1, 'watcher': 1})
    st, d = call('/api/auth/passkeys', 'POST', {'do': 'reset', 'name': 'watcher'}, session=tok)
    ok('a full admin may: their passkeys gone', (st, store.passkeys('watcher')), (200, []))
    ok('...the next sign-in sets Face ID up again', login('watcher', 'another-long-password')[1],
       'enrol')
    ev = [r['detail'] for r in store.db.execute("SELECT detail FROM events ORDER BY ts DESC LIMIT 40")]
    ok('...and it is written down', any('set Face ID up again for watcher' in m for m in ev))

    print('\nAnother device, and taking one away')
    st, d = call('/api/auth/passkey', 'POST', {'step': 'begin', 'want': 'enrol'}, session=tok)
    mac = Device(folder_dev)
    st, d = call('/api/auth/passkey', 'POST', dict(mac.make(d['publicKey']), step='enrol',
                                                    name='Mac'), session=tok)
    ok('a whole sign-in adds another device', (st, len(store.passkeys('boss'))), (200, 2))
    st, d = call('/api/auth/passkeys', session=tok)
    ok('...listed, without the keys', (len(d['passkeys']), 'pem' in d['passkeys'][0], d['here']),
       (2, False, RP))
    st, d = call('/api/auth/passkeys', 'POST', {'do': 'delete', 'id': b64(mac.cid)},
                 session=login('watcher', 'another-long-password')[0])
    ok('somebody else\'s: not theirs to take away', st, 403)
    st, d = call('/api/auth/passkeys', 'POST', {'do': 'delete', 'id': b64(mac.cid)}, session=tok)
    ok('...their own: taken away', len(store.passkeys('boss')), 1)

    print('\nWhat the review found (1.10.303)')
    st, d = call('/api/auth/passkey', 'POST', {'step': 'begin', 'want': 'enrol'}, session=tok)
    ok('another device just after Face ID: offered', st, 200)
    isemon.PK_FRESH.clear()
    st, d = call('/api/auth/passkey', 'POST', {'step': 'begin', 'want': 'enrol'}, session=tok)
    ok('...a while after it: Face ID first', (st, 'confirm it is you' in d.get('error', '')),
       (428, True))
    st, d = call('/api/auth/passkeys', session=tok)
    ok('...and the page is told', d.get('fresh'), False)
    st, d = call('/api/auth/passkey', 'POST', {'step': 'begin', 'want': 'check'}, session=tok,
                 host='localhost:6666', https=False)
    ok('localhost from another machine: no Face ID', st, 409)
    h_tok, second = login()
    store.put_user_prefs('boss', {'lang': 'cs'})
    st, d = call('/api/auth/whoami', session=h_tok)
    ok('half a sign-in is told who it is and nothing it keeps',
       (d['who']['second'], d['prefs'], d['finds']), ('verify', {}, []))
    with store.db_write() as db:
        for n in ('jnovak', 'jnovak@corp.example'):
            db.execute("INSERT INTO users (name, role, hash, made, made_by, disabled, from_dir, dn) "
                       "VALUES (?, 'readonly', '', 0, 'test', 0, 1, 'CN=Jan Novak,DC=corp')", (n,))
    keys = store.passkeys()
    keys.append({'id': 'j1', 'user': 'jnovak', 'name': 'iPad', 'pem': '', 'alg': -7, 'count': 0,
                 'created': 0, 'last_used': 0, 'host': RP})
    store.put_passkeys(keys)
    ok('out of the directory, the other name of the person owes the passkey of the first',
       daemon.second_owed('jnovak@corp.example'), 'verify')
    store.drop_user('jnovak')
    ok('an account removed takes its passkeys with it',
       [k['id'] for k in store.passkeys() if k['user'] == 'jnovak'], [])
    w_tok2, second = login('watcher', 'another-long-password')
    ok('a full admin\'s reset ends the person\'s sign-ins as well',
       (call('/api/auth/passkeys', 'POST', {'do': 'reset', 'name': 'watcher'},
             session=tok)[1].get('ended', 0) >= 1, call('/api/auth/whoami',
                                                        session=w_tok2)[1].get('who')),
       (True, None))
    isemon.CONFIG['passkeys'] = 0
    ok('Face ID switched off: a half sign-in ends, it does not become whole',
       call('/api/status', session=h_tok)[0], 401)
    isemon.CONFIG['passkeys'] = 1

    print('\nFrom the command line')
    said = []
    pal = types.SimpleNamespace(good=said.append, bad=said.append, note=said.append)
    isemon.cmd_passkey_reset(types.SimpleNamespace(passkey_reset='boss'), pal, store)
    ok('isemon --passkey-reset NAME', (store.passkeys('boss'), 'next sign-in' in said[-1]),
       ([], True))

    print('\nThe keys a device may have')
    k = os.path.join(folder_dev, 'rsa.pem')
    ossl('genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', k)
    pub = ossl('pkey', '-in', k, '-pubout').decode()
    mod = ossl('rsa', '-in', k, '-noout', '-modulus').decode().strip().split('=')[1]
    pem, alg = isemon.pk_cose_pem({1: 3, 3: -257, -1: bytes.fromhex(mod),
                                   -2: (65537).to_bytes(3, 'big')})
    ok('RSA (Windows Hello): the same key as openssl\'s', (pem.strip(), alg), (pub.strip(), -257))
    sig = ossl('dgst', '-sha256', '-sign', k, data=b'data')
    ok('...its signature checked', isemon.pk_verify(pem, -257, b'data', sig))
    e = os.path.join(folder_dev, 'ed.pem')
    ossl('genpkey', '-algorithm', 'ED25519', '-out', e)
    raw = ossl('pkey', '-in', e, '-pubout', '-outform', 'DER')[-32:]
    pem, alg = isemon.pk_cose_pem({1: 1, 3: -8, -1: 6, -2: raw})
    data = os.path.join(folder_dev, 'data')
    Path(data).write_bytes(b'data')
    sig = ossl('pkeyutl', '-sign', '-inkey', e, '-rawin', '-in', data)
    ok('Ed25519: checked', (isemon.pk_verify(pem, -8, b'data', sig),
                            isemon.pk_verify(pem, -8, b'other', sig)), (True, False))
    try:
        isemon.pk_cose_pem({1: 3, 3: -257, -1: b'\xff' * 128, -2: b'\x01\x00\x01'})
        ok('an RSA key of 1024 bits: refused', False)
    except ValueError:
        ok('an RSA key of 1024 bits: refused', True)
    try:
        isemon.pk_cbor(b'\x5a\xff\xff\xff\xff')
        ok('CBOR that says it is longer than it is: refused', False)
    except ValueError:
        ok('CBOR that says it is longer than it is: refused', True)

    print('\nThe page')
    page = (HERE.parent / 'web' / 'index.php').read_text()
    ok('half a sign-in is the door still, with the second step on it',
       ("$second  = ($me && !empty($me['second'])) ? (string) $me['second'] : '';" in page,
        'id="pk-step"' in page, 'if (got.d.second) {' in page), (True, True, True))
    ok('the page tells the daemon its name and whether over TLS',
       "X-Isemon-Https: ' . (isemon_https() ? '1' : '0')" in
       (HERE.parent / 'web' / 'isemon-api.php').read_text())
    ok('a full admin sets it up again from Accounts', "api('passkeys', {do: 'reset', name: u.name})"
       in page)
finally:
    api.stop() if hasattr(api, 'stop') else None
    shutil.rmtree(folder, ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
