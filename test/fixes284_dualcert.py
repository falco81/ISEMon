#!/usr/bin/env python3
"""1.10.284: a dual certificate (RSA and ECDSA side by side) uploaded and
downloaded on Certificates and TLS.

- Upload: the two pairs at once - their PEM files in any order, or two PFX
  files under one password; each sorted and checked as one alone is, the
  RSA one kept as the certificate and the ECDSA one beside it (as Automatic
  certificates keeps a dual one). Two of one kind, a key of neither, a twin
  that ran out: refused, nothing changed. One certificate alone: as before,
  and the twin beside the old one goes.
- Download: which - the first (as ever, the default), the second, or both
  in one ZIP, each in the format asked with its own chain and key; the key
  only to a full administrator, and said in Events.
- What is downloaded as both goes back up as it came.

    ./test/fixes284_dualcert.py
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


def make(kind, name='isemon.example.cz', days=60):
    d = tempfile.mkdtemp(prefix='isemon-284-c-')
    try:
        key = os.path.join(d, 'k')
        if kind == 'ec':
            subprocess.run(['openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt',
                            'ec_paramgen_curve:P-256', '-out', key], check=True, capture_output=True)
        else:
            subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt',
                            'rsa_keygen_bits:2048', '-out', key], check=True, capture_output=True)
        subprocess.run(['openssl', 'req', '-new', '-x509', '-key', key, '-days', str(days),
                        '-subj', '/CN=' + name, '-addext', 'subjectAltName=DNS:' + name,
                        '-out', os.path.join(d, 'c')], check=True, capture_output=True)
        cert, k = open(os.path.join(d, 'c')).read(), open(key).read()
        pfx = subprocess.run(['openssl', 'pkcs12', '-export', '-in', os.path.join(d, 'c'), '-inkey',
                              key, '-passout', 'pass:Pfx-Password-1'], check=True,
                             capture_output=True).stdout
        return cert, k, base64.b64encode(pfx).decode()
    finally:
        shutil.rmtree(d, ignore_errors=True)


def fp(pem):
    return isemon.push_fingerprint(pem)


work = Path(tempfile.mkdtemp(prefix='isemon-284-'))
try:
    state = work / 'state'
    state.mkdir()
    isemon.STATE_DIR = state
    isemon.DB_FILE = state / 'd.db'
    isemon.BACKUP_DIR = state / 'b'
    isemon.DUMP_DIR = state / 'dumps'
    isemon.RUN_DIR = state
    isemon.LOG_DIR = state
    isemon.CONFIG_FILE = state / 'config.json'
    isemon._LOG_PATH = state / 'd.log'
    isemon.TOKEN_FILE = state / 'token'
    isemon.CONFIG.clear()
    isemon.CONFIG.update(isemon.DEFAULTS)
    isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0})
    (state / 'config.json').write_text(json.dumps({'db_engine': 'sqlite'}))
    store = isemon.Storage(isemon.DB_FILE)
    daemon = isemon.Daemon(store)
    wr = daemon.webroot
    rc, rk, rpfx = make('rsa')
    ec, ek, epfx = make('ec')

    print('Upload: one alone, as ever')
    got = wr.tls_do({'action': 'upload', 'pem': [ec, ek]}, by='boss')
    tls = wr.tls_conf()
    ok('kept, no twin', (got['ok'], fp(tls['cert']), isemon.tls_second(tls)), (True, fp(ec), None))
    ok('...the download view offers no second', wr.tls_export_view()['second'], None)

    print('\nUpload: a dual one')
    for words, pem in (('RSA first', [rc, rk, ec, ek]), ('ECDSA first, the keys apart',
                                                         [ek, ec + rc, rk])):
        got = wr.tls_do({'action': 'upload', 'pem': pem}, by='boss')
        tls = wr.tls_conf()
        ok('two PEM pairs (%s): RSA the certificate, ECDSA beside it, tied, said' % words, (
            fp(tls['cert']), fp(tls['cert2']), bool(isemon.tls_second(tls)),
            'with the ECDSA one beside it' in got['message'], tls['how']),
           (fp(rc), fp(ec), True, True, 'uploaded'))
    ok('...both keys sealed, each its own certificate\'s', (
        isemon.key_pubkey(isemon.unseal_secret(tls['key']))[1] == isemon.key_pubkey(rk)[1],
        isemon.key_pubkey(isemon.unseal_secret(tls['key2']))[1] == isemon.key_pubkey(ek)[1],
        rk.strip() not in json.dumps(tls), ek.strip() not in json.dumps(tls)), (True,) * 4)
    ok('...Automatic certificates leave it alone, as after any upload', isemon.acme_care(wr), False)
    wr.tls_do({'action': 'upload', 'pem': [ec, ek]}, by='boss')
    ok('one alone afterwards: the twin goes, as before', isemon.tls_second(wr.tls_conf()), None)
    got = wr.tls_do({'action': 'upload', 'pem': [], 'pfx': epfx, 'pfx2': rpfx,
                     'password': 'Pfx-Password-1'}, by='boss')
    tls = wr.tls_conf()
    ok('two PFX files under one password: the same', (fp(tls['cert']), fp(tls['cert2'])),
       (fp(rc), fp(ec)))

    print('\nRefused, nothing changed')
    before = json.dumps(wr.tls_conf(), sort_keys=True)
    r2c, r2k, _ = make('rsa')
    e2c, e2k, _ = make('ec')
    old, old_k, _ = make('ec', days=1)
    for words, data, want in (
            ('two RSA', {'pem': [rc, rk, r2c, r2k]}, 'one RSA and one ECDSA'),
            ('two ECDSA', {'pem': [ec, ek, e2c, e2k]}, 'one RSA and one ECDSA'),
            ('two keys of one certificate', {'pem': [rc, rk, rk]}, ''),
            ('a key of no certificate sent', {'pem': [rc, rk, e2k]}, 'not the one'),
            ('a second PFX alone', {'pem': [], 'pfx2': rpfx, 'password': 'Pfx-Password-1'},
             'send the first one with it'),
            ('the PFX password wrong', {'pem': [], 'pfx': epfx, 'pfx2': rpfx, 'password': 'no'}, '')):
        try:
            wr.tls_do(dict(data, action='upload'), by='boss')
            said = None
        except isemon.WebRootError as e:
            said = str(e)
        ok('%s: refused%s' % (words, (' (%s)' % want) if want else ''),
           said is not None and want in (said or ''))
    ok('...and the dual one kept as it was', json.dumps(wr.tls_conf(), sort_keys=True), before)

    print('\nDownload')
    view = wr.tls_export_view()
    ok('the view offers the second, with its key, in words', (view['second']['key'],
                                                             view['second']['words']),
       (True, ['RSA 2048 bit', 'EC 256 bit']))
    main = wr.tls_export({'format': 'pem', 'chain': False}, admin=True)
    ok('the first, as ever (the default): the RSA certificate', (main['name'], fp(main['data'].decode())),
       ('isemon.example.cz.pem', fp(rc)))
    two = wr.tls_export({'format': 'pem', 'which': 'second'}, admin=True)
    ok('the second: the ECDSA one', fp(two['data'].decode()), fp(ec))
    both = wr.tls_export({'format': 'pfx', 'which': 'both', 'password': 'Export-Pass-1'}, by='boss',
                         admin=True)
    z = zipfile.ZipFile(io.BytesIO(both['data']))
    ok('both: one ZIP, a file of each kind', (both['name'], sorted(z.namelist())),
       ('isemon.example.cz-both.zip', ['isemon.example.cz-ecdsa.pfx', 'isemon.example.cz-rsa.pfx']))
    opened = {}
    for n in z.namelist():
        f = work / n
        f.write_bytes(z.read(n))
        out = subprocess.run(['openssl', 'pkcs12', '-in', str(f), '-nodes', '-passin',
                              'pass:Export-Pass-1'], capture_output=True, text=True).stdout
        opened[n] = out
    ok('...each PFX opens with the password: its certificate and its own key', (
        fp(opened['isemon.example.cz-rsa.pfx']) == fp(rc),
        isemon.key_pubkey(isemon.PEM_KEY_RE.search(opened['isemon.example.cz-rsa.pfx']).group(0))[1]
        == isemon.key_pubkey(rk)[1],
        fp(opened['isemon.example.cz-ecdsa.pfx']) == fp(ec),
        isemon.key_pubkey(isemon.PEM_KEY_RE.search(opened['isemon.example.cz-ecdsa.pfx']).group(0))[1]
        == isemon.key_pubkey(ek)[1]), (True,) * 4)
    ok('...said in Events: both certificates with both keys', any(
        'both certificates with both keys' in (e['detail'] or '') for e in store.events(limit=10)[0]))
    try:
        wr.tls_export({'format': 'key', 'which': 'both'}, admin=False)
        ok('a key, for one who is not a full administrator: refused', False)
    except isemon.WebRootError:
        ok('a key, for one who is not a full administrator: refused', True)
    pem_both = wr.tls_export({'format': 'pem_key', 'which': 'both'}, admin=True)
    z = zipfile.ZipFile(io.BytesIO(pem_both['data']))
    files = [z.read(n).decode() for n in sorted(z.namelist())]

    print('\nWhat came down goes back up')
    wr.tls_do({'action': 'upload', 'pem': [ec, ek]}, by='boss')
    got = wr.tls_do({'action': 'upload', 'pem': files}, by='boss')
    tls = wr.tls_conf()
    ok('the two PEM files of the ZIP uploaded: the same pair again', (fp(tls['cert']),
                                                                    fp(tls['cert2'])),
       (fp(rc), fp(ec)))
    wr.tls_do({'action': 'upload', 'pem': [ec, ek]}, by='boss')
    try:
        wr.tls_export({'format': 'pem', 'which': 'both'}, admin=True)
        ok('both, of a certificate with no twin: refused', False)
    except isemon.WebRootError as e:
        ok('both, of a certificate with no twin: refused', 'no second certificate' in str(e))

    print('\nThe page')
    page = (ROOT / 'web' / 'index.php').read_text()
    ok('Download: which certificate, for a dual one', (
        "two.appendChild(el('h4', '', 'Which certificate'));" in page,
        "which: st.which}).then(function (x) {" in page), (True, True))
    ok('Upload: two PFX files, or two PEM pairs', (
        "pfx2: pfx.length > 1 ? pfx[1].pfx : ''," in page,
        "if (pfx.length > 2) { toast(" in page), (True, True))
finally:
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
