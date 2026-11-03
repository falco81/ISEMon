#!/usr/bin/env python3
"""1.10.285: a ZIP uploaded on Certificates and TLS - Download's of both, or
one from a CA - its files taken as though each had been chosen by itself.

Unpacked by the daemon in memory with limits (20 files, 256 KiB each, 1 MiB
in all, unpacked), a locked ZIP refused, files that are no certificate (a
README) left alone; PEM, PFX and DER in it sorted as ever, two PFX in it (or
one in it and one beside it) a dual certificate under one password.

    ./test/fixes285_zip.py
"""
import base64
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
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


def make(kind, name='isemon.example.cz'):
    d = tempfile.mkdtemp(prefix='isemon-285-c-')
    try:
        key = os.path.join(d, 'k')
        algo = (['-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256'] if kind == 'ec'
                else ['-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048'])
        subprocess.run(['openssl', 'genpkey'] + algo + ['-out', key], check=True, capture_output=True)
        subprocess.run(['openssl', 'req', '-new', '-x509', '-key', key, '-days', '60',
                        '-subj', '/CN=' + name, '-addext', 'subjectAltName=DNS:' + name,
                        '-out', os.path.join(d, 'c')], check=True, capture_output=True)
        cert, k = open(os.path.join(d, 'c')).read(), open(key).read()
        pfx = subprocess.run(['openssl', 'pkcs12', '-export', '-in', os.path.join(d, 'c'), '-inkey',
                              key, '-passout', 'pass:Pfx-Password-1'], check=True,
                             capture_output=True).stdout
        return cert, k, pfx
    finally:
        shutil.rmtree(d, ignore_errors=True)


def zipped(files, locked=False):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        for name, data in files:
            info = zipfile.ZipInfo(name)
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, data)
    raw = bytearray(buf.getvalue())
    if locked:
        # As a ZIP locked with a password says so: the bit in the local and
        # the central header (Python writes none, and reads it back).
        for sig, at in ((b'PK\x03\x04', 6), (b'PK\x01\x02', 8)):
            i = raw.find(sig)
            while i >= 0:
                raw[i + at] |= 1
                i = raw.find(sig, i + 4)
    return base64.b64encode(bytes(raw)).decode()


def fp(pem):
    return isemon.push_fingerprint(pem)


work = Path(tempfile.mkdtemp(prefix='isemon-285-'))
try:
    state = work / 'state'
    state.mkdir()
    for k, v in (('STATE_DIR', state), ('DB_FILE', state / 'd.db'), ('BACKUP_DIR', state / 'b'),
                 ('DUMP_DIR', state / 'dumps'), ('RUN_DIR', state), ('LOG_DIR', state),
                 ('CONFIG_FILE', state / 'config.json'), ('_LOG_PATH', state / 'd.log'),
                 ('TOKEN_FILE', state / 'token')):
        setattr(isemon, k, v)
    isemon.CONFIG.clear()
    isemon.CONFIG.update(isemon.DEFAULTS)
    isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0})
    (state / 'config.json').write_text(json.dumps({'db_engine': 'sqlite'}))
    store = isemon.Storage(isemon.DB_FILE)
    daemon = isemon.Daemon(store)
    wr = daemon.webroot
    rc, rk, rpfx = make('rsa')
    ec, ek, epfx = make('ec')

    def up(**data):
        return wr.tls_do(dict({'action': 'upload', 'pem': []}, **data), by='boss')

    def pair():
        t = wr.tls_conf()
        return (fp(t.get('cert')), fp(t.get('cert2')) if isemon.tls_second(t) else '')

    print('What Download gives, back up')
    up(pem=[rc, rk, ec, ek])
    for fmt, pw in (('pfx', 'Export-Pass-1'), ('pem_key', '')):
        got = wr.tls_export({'format': fmt, 'which': 'both', 'password': pw}, admin=True)
        up(pem=[ec, ek])
        ok('one alone in between', pair(), (fp(ec), ''))
        said = up(zip=[base64.b64encode(got['data']).decode()], password=pw)
        ok('the ZIP of both (%s): the same pair again, said' % fmt,
           (pair(), 'with the ECDSA one beside it' in said['message']), ((fp(rc), fp(ec)), True))

    print('\nWhat a CA sends')
    up(zip=[zipped([('cert.pem', rc), ('chain/README.txt', 'read me'), ('private.key', rk)])])
    ok('PEM files in it, a README beside them: the certificate and its key', pair(), (fp(rc), ''))
    up(zip=[zipped([('server.p12', rpfx)])], password='Pfx-Password-1')
    ok('one PFX in it', pair(), (fp(rc), ''))
    der = subprocess.run(['openssl', 'x509', '-outform', 'DER'], input=ec.encode(),
                         capture_output=True).stdout
    up(zip=[zipped([('server.cer', der), ('server.key', ek)])])
    ok('a DER certificate and its key', pair(), (fp(ec), ''))
    up(zip=[zipped([('a.pfx', epfx)])], pfx=base64.b64encode(rpfx).decode(),
       password='Pfx-Password-1')
    ok('one PFX in the ZIP and one beside it: a dual one', pair(), (fp(rc), fp(ec)))

    print('\nRefused, nothing changed')
    before = json.dumps(wr.tls_conf(), sort_keys=True)
    bomb = io.BytesIO()
    with zipfile.ZipFile(bomb, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr('big.pem', b'-----BEGIN CERTIFICATE-----\n' + b'A' * (5 << 20))
    for words, data, want in (
            ('a ZIP locked with a password', {'zip': [zipped([('c.pem', rc)], locked=True)]},
             'locked with a password'),
            ('a file in it unpacking to megabytes', {'zip': [base64.b64encode(bomb.getvalue())
                                                             .decode()]}, 'far bigger'),
            ('thirty files in it', {'zip': [zipped([('f%d.pem' % i, rc) for i in range(30)])]},
             'holds 30 files'),
            ('nothing of a certificate in it', {'zip': [zipped([('README.txt', 'hello')])]},
             'no certificate file'),
            ('not a ZIP', {'zip': [base64.b64encode(b'not a zip at all').decode()]}, 'not a ZIP'),
            ('three PFX in all', {'zip': [zipped([('a.pfx', epfx), ('b.pfx', rpfx)])],
                                  'pfx': base64.b64encode(rpfx).decode(),
                                  'password': 'Pfx-Password-1'}, 'these are 3')):
        try:
            up(**data)
            said = None
        except isemon.WebRootError as e:
            said = str(e)
        ok('%s: refused (%s)' % (words, want), said is not None and want in said)
    ok('...and the certificates kept as they were', json.dumps(wr.tls_conf(), sort_keys=True),
       before)
    ok('nothing unpacked anywhere on the disk', sorted(p.name for p in state.iterdir()
                                                       if p.suffix in ('.pem', '.pfx', '.zip')), [])

    print('\nThe page')
    page = (ROOT / 'web' / 'index.php').read_text()
    ok('a ZIP chosen, sent as it is', (
        "inp.accept = '.pem,.crt,.cer,.key,.pfx,.p12,.chain,.ca,.txt,.zip';" in page,
        "ok({name: f.name, zip: btoa(zb)});" in page, "zip: zips," in page), (True,) * 3)
finally:
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
