#!/usr/bin/env python3
"""1.10.249: Settings → Certificates and TLS → Download - the certificate in
the format chosen: PEM, DER, PKCS#7, PFX (and a PFX for older systems), PEM
with the private key, or the key alone. The private key goes out only to a
full administrator, under a password that goes to openssl by the environment
and is kept nowhere; every export with a key is written to Events. Every file
made is read back here by openssl.

    ./test/fixes249_export.py
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
import isemon                                        # noqa: E402

PASS = FAIL = 0
PW = 'Export-Password-249'


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


work = Path(tempfile.mkdtemp(prefix='isemon-249-'))
try:
    state = work / 'state'
    (state / 'web').mkdir(parents=True)
    isemon.STATE_DIR = state
    isemon.CONFIG.clear()
    isemon.CONFIG.update(isemon.DEFAULTS)
    store = isemon.Storage(state / 'isemon.db')

    class D(object):
        pass
    d = D()
    d.store = store
    wr = isemon.WebRoot(d)
    # An authority, an intermediate and the server's certificate.
    os.chdir(str(work))
    for args in (
            ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '30', '-subj', '/CN=Test Root',
             '-keyout', 'root.key', '-out', 'root.pem', '-addext', 'basicConstraints=critical,CA:TRUE'],
            ['req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=Test Issuing',
             '-keyout', 'mid.key', '-out', 'mid.csr'],
            ['req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=isemon.example.net',
             '-keyout', 'srv.key', '-out', 'srv.csr']):
        assert sh(['openssl'] + args).returncode == 0
    (work / 'ca.ext').write_text('basicConstraints=critical,CA:TRUE\n')
    assert sh(['openssl', 'x509', '-req', '-in', 'mid.csr', '-CA', 'root.pem', '-CAkey', 'root.key',
               '-CAcreateserial', '-days', '30', '-extfile', 'ca.ext', '-out', 'mid.pem']).returncode == 0
    assert sh(['openssl', 'x509', '-req', '-in', 'srv.csr', '-CA', 'mid.pem', '-CAkey', 'mid.key',
               '-CAcreateserial', '-days', '30', '-out', 'srv.pem']).returncode == 0
    CERT, KEY = (work / 'srv.pem').read_text(), (work / 'srv.key').read_text()
    MID, ROOTC = (work / 'mid.pem').read_text(), (work / 'root.pem').read_text()

    print('Nothing looked after yet, no certificate known')
    try:
        wr.tls_export({'format': 'pem'}, 'boss', admin=True)
        ok('refused, and said', False)
    except isemon.WebRootError as e:
        ok('refused, and said', 'no certificate' in str(e))

    print('\nnginx\'s own certificate (never uploaded): the certificate only')
    (state / 'web' / 'look.json').write_text(json.dumps({'at': 9e9, 'cert': {'pem': CERT + MID}}))
    v = wr.tls_export_view()
    ok('the view: a certificate, no key', (v['cert'], v['key'], v['managed']), (True, False, False))
    got = wr.tls_export({'format': 'pem'}, 'boss', admin=True)
    ok('PEM: the certificate and its chain', got['data'].decode().count('BEGIN CERTIFICATE'), 2)
    try:
        wr.tls_export({'format': 'pfx', 'password': PW}, 'boss', admin=True)
        ok('a PFX: refused - isemon holds no key', False)
    except isemon.WebRootError as e:
        ok('a PFX: refused - isemon holds no key', 'does not hold' in str(e))

    print('\nThe certificate isemon looks after, with its key')
    wr._put('web_tls', {'managed': True, 'cert': CERT, 'chain': MID, 'root': ROOTC,
                        'key': isemon.seal_secret(KEY)})
    v = wr.tls_export_view()
    ok('the view: a certificate, its key, a chain (the issuing one and the root)',
       (v['cert'], v['key'], v['chain_n']), (True, True, 2))
    ok('seven formats', [f['id'] for f in v['formats']],
       ['pem', 'pem_key', 'der', 'p7b', 'pfx', 'pfx_legacy', 'key'])

    def keep(got, name):
        p = work / name
        p.write_bytes(got['data'])
        return str(p)

    got = wr.tls_export({'format': 'pem'}, 'boss')
    ok('PEM: the certificate, the chain and the root, no key',
       (got['data'].decode().count('BEGIN CERTIFICATE'), b'PRIVATE' in got['data'],
        got['name']), (3, False, 'isemon.example.net.pem'))
    got = wr.tls_export({'format': 'pem', 'chain': False}, 'boss')
    ok('...without the chain: the certificate alone', got['data'].decode().count('BEGIN CERTIFICATE'), 1)
    got = wr.tls_export({'format': 'der'}, 'boss')
    f = keep(got, 'c.cer')
    ok('DER: openssl reads it', (sh(['openssl', 'x509', '-inform', 'DER', '-in', f, '-noout']).returncode,
                                  got['name']), (0, 'isemon.example.net.cer'))
    got = wr.tls_export({'format': 'p7b'}, 'boss')
    f = keep(got, 'c.p7b')
    out = sh(['openssl', 'pkcs7', '-inform', 'DER', '-in', f, '-print_certs']).stdout.decode()
    ok('PKCS#7: the certificate and its chain in it', out.count('BEGIN CERTIFICATE'), 3)

    print('\nWith the private key')
    for fmt in ('pfx', 'pfx_legacy', 'pem_key', 'key'):
        try:
            wr.tls_export({'format': fmt, 'password': PW}, 'reader', admin=False)
            ok('%s: not for an account that is no full administrator' % fmt, False)
        except isemon.WebRootError as e:
            ok('%s: not for an account that is no full administrator' % fmt, 'full administrator' in str(e))
    try:
        wr.tls_export({'format': 'pfx', 'password': 'short'}, 'boss', admin=True)
        ok('a PFX under a short password: refused', False)
    except isemon.WebRootError as e:
        ok('a PFX under a short password: refused', '8 characters' in str(e))
    try:
        wr.tls_export({'format': 'pfx', 'password': ''}, 'boss', admin=True)
        ok('...and under none', False)
    except isemon.WebRootError:
        ok('...and under none', True)
    env = dict(os.environ, P=PW)
    got = wr.tls_export({'format': 'pfx', 'password': PW}, 'boss', admin=True)
    f = keep(got, 'c.pfx')
    out = sh(['openssl', 'pkcs12', '-in', f, '-passin', 'env:P', '-nodes'], env=env)
    ok('PFX: opened with the password - the key and the three certificates',
       (out.returncode, out.stdout.decode().count('BEGIN CERTIFICATE'),
        'PRIVATE KEY' in out.stdout.decode(), got['name']),
       (0, 3, True, 'isemon.example.net.pfx'))
    info = sh(['openssl', 'pkcs12', '-in', f, '-passin', 'env:P', '-info', '-noout'], env=env)
    ok('...AES-256 and SHA-256', ('AES-256-CBC' in info.stderr.decode() + info.stdout.decode(),
                                  'sha256' in (info.stderr.decode() + info.stdout.decode()).lower()),
       (True, True))
    out = sh(['openssl', 'pkcs12', '-in', f, '-passin', 'pass:wrong-one', '-nodes'])
    ok('...not with another password', out.returncode != 0)
    got = wr.tls_export({'format': 'pfx_legacy', 'password': PW}, 'boss', admin=True)
    f = keep(got, 'l.pfx')
    info = sh(['openssl', 'pkcs12', '-in', f, '-passin', 'env:P', '-info', '-noout'], env=env)
    words = info.stderr.decode() + info.stdout.decode()
    ok('PFX for older systems: 3DES and SHA-1 - what Windows Server 2016 opens',
       (info.returncode, '3-KeyTripleDES' in words, 'sha1' in words.lower()), (0, True, True))
    got = wr.tls_export({'format': 'pem_key', 'password': PW}, 'boss', admin=True)
    text = got['data'].decode()
    ok('PEM with the key, encrypted', (text.count('BEGIN CERTIFICATE'),
                                       'BEGIN ENCRYPTED PRIVATE KEY' in text), (3, True))
    f = keep(got, 'k.pem')
    ok('...opened with the password', sh(['openssl', 'pkey', '-in', f, '-passin', 'env:P', '-noout'],
                                         env=env).returncode, 0)
    got = wr.tls_export({'format': 'key'}, 'boss', admin=True)
    ok('the key alone, not encrypted when no password is given',
       (got['data'].decode().startswith('-----BEGIN PRIVATE KEY'), got['name']),
       (True, 'isemon.example.net.key'))
    ok('...the key that is the certificate\'s',
       sh(['openssl', 'pkey', '-pubout'], data=got['data']).stdout ==
       sh(['openssl', 'x509', '-pubkey', '-noout'], data=CERT.encode()).stdout)

    print('\nWhat is kept of it')
    ev = [e['detail'] for e in store.events(limit=50)[0]]
    ok('every export with the key in Events, with who and how',
       (len([e for e in ev if 'exported the certificate' in e]),
        any('boss exported the certificate of the pages with its private key (PKCS#12 (PFX)'
            in e for e in ev)), (4, True))
    ok('...the exports without one are not', any('(PEM, ' in e or 'DER' in e for e in ev), False)
    ok('the password nowhere in the database', PW.encode() in (state / 'isemon.db').read_bytes(), False)
    ok('...nor the key unsealed', b'BEGIN PRIVATE KEY' in (state / 'isemon.db').read_bytes(), False)

    print('\nThe page')
    page = (ROOT / 'web' / 'index.php').read_text()
    ok('Download opens the popup of the formats', ('dl.onclick = function () { certExport(d); };' in page,
                                                    'function certExport(d)' in page), (True, True))
    ok('...asked through the relay', page.count("'web-tls-export' => '/api/web/tls/export',"), 2)
    ok('...the password typed twice', ("pw.id = 'ce-pw'" in page, "pw2.id = 'ce-pw2'" in page),
       (True, True))
    ok('...the bytes saved as they came', 'function saveBytes(name, b64)' in page)
finally:
    os.chdir('/')
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
