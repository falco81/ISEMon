#!/usr/bin/env python3
"""1.10.352: a certificate request made in the browser. The page's own
functions (between csr-begin and csr-end in web/index.php) are run in node
with its WebCrypto, and openssl checks what they make: the signature, the
subject, the UPN, the URL of the SID, the mail, the key usages - for every
kind of key. Without node, the static checks only.

    ./test/fixes352_csr.py
"""
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
page = (HERE.parent / 'web' / 'index.php').read_text()
PASS = FAIL = 0


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


lib = page[page.index('/* csr-begin'):page.index('/* csr-end */')]
print('the page')
ok('the key is made by WebCrypto, nothing of it sent', 'api(' not in lib and 'fetch(' not in lib
   and 'XMLHttpRequest' not in lib)
ok('the popup has the button', "certCsrForm(p)" in page and "'Make a request (CSR)…'" in page)
ok('...and saves both files', "saveText(base + '.csr', r.csr)" in page and "saveText(base + '.key', r.key)" in page)

node = shutil.which('node')
ossl = shutil.which('openssl')
if not node or not ossl:
    print('  skip  no node or openssl here: the requests are not made')
else:
    work = Path(tempfile.mkdtemp(prefix='isemon-352csr-'))
    try:
        sid = 'tag:microsoft.com,2022-09-14:sid:S-1-5-21-1345087706-903693047-1615293757-16480'
        cases = [
            ('ec256', dict(kind='ec256', cn='Jana Testová', o='Example s.r.o.', ou='IT', c='CZ',
                           upn='jtestova@corpnet.cz', url=sid, mail='jana@corpnet.cz',
                           client=True, smartcard=True)),
            ('ec384', dict(kind='ec384', cn='jtestova', upn='jtestova@corpnet.cz', url='', mail='',
                           client=True, smartcard=False)),
            ('rsa2048', dict(kind='rsa2048', cn='Jana Testova', upn='jtestova@corpnet.cz', url=sid,
                             mail='', client=True, smartcard=True)),
            ('rsa4096', dict(kind='rsa4096', cn='x', upn='', url='', mail='', client=False,
                             smartcard=False)),
        ]
        js = lib + '\nconst cases = ' + json.dumps(cases) + ''';
const fs = require('fs');
(async () => {
  for (const [n, o] of cases) {
    const r = await csrMake(o, globalThis.crypto.subtle);
    fs.writeFileSync(process.argv[2] + '/' + n + '.csr', r.csr);
    fs.writeFileSync(process.argv[2] + '/' + n + '.key', r.key);
  }
  for (const bad of [{kind: 'ec256', cn: ''}, {kind: 'nope', cn: 'x'}, {kind: 'ec256', cn: 'x', c: 'cze'},
                     {kind: 'ec256', cn: 'x', url: 'tag:ž'}]) {
    try { await csrMake(bad, globalThis.crypto.subtle); console.log('MADE'); }
    catch (e) { console.log('refused: ' + e.message); }
  }
})().catch(e => { console.log('ERROR ' + e.stack); process.exit(1); });
'''
        (work / 'run.js').write_text(js)
        r = subprocess.run([node, str(work / 'run.js'), str(work)], capture_output=True, text=True,
                           timeout=180)
        lines = r.stdout.strip().splitlines()
        ok('node made them all', r.returncode, 0)
        ok('bad asks refused', [l.startswith('refused') for l in lines], [True] * 4)
        for n, o in cases:
            csr, key = work / (n + '.csr'), work / (n + '.key')
            v = subprocess.run([ossl, 'req', '-in', str(csr), '-noout', '-verify', '-text',
                                '-nameopt', 'utf8'], capture_output=True, text=True)
            txt = v.stdout + v.stderr
            ok('%s: the signature holds' % n, v.returncode == 0 and 'verify OK' in txt.replace(
                'Certificate request self-signature verify OK', 'verify OK'))
            ok('%s: CN' % n, ('CN=%s' % o['cn']) in txt or ('CN = %s' % o['cn']) in txt)
            if o.get('c'):
                ok('%s: C, O, OU' % n, all(s in txt.replace(' = ', '=') for s in
                                           ('C=CZ', 'O=Example s.r.o.', 'OU=IT')))
            ok('%s: the UPN' % n, ('jtestova@corpnet.cz' in txt and
                                   ('Universal Principal Name' in txt or 'othername' in txt.lower()))
               == bool(o['upn']))
            ok('%s: the URL of the SID' % n, ('URI:' + sid in txt) == bool(o['url']))
            ok('%s: the mail' % n, ('email:jana@corpnet.cz' in txt) == bool(o['mail']))
            ok('%s: client authentication' % n, ('TLS Web Client Authentication' in txt) == o['client'])
            ok('%s: smart card logon' % n, ('Microsoft Smartcard Login' in txt
                                            or '1.3.6.1.4.1.311.20.2.2' in txt) == o['smartcard'])
            ok('%s: key usage critical' % n, 'X509v3 Key Usage: critical' in txt)
            bits = {'ec256': '256 bit', 'ec384': '384 bit', 'rsa2048': '2048 bit', 'rsa4096': '4096 bit'}[n]
            ok('%s: the key, %s' % (n, bits), bits in txt)
            k = subprocess.run([ossl, 'pkey', '-in', str(key), '-pubout'], capture_output=True, text=True)
            c = subprocess.run([ossl, 'req', '-in', str(csr), '-noout', '-pubkey'], capture_output=True,
                               text=True)
            ok('%s: the key saved is the one of the request' % n, k.stdout.strip() == c.stdout.strip()
               and bool(k.stdout.strip()))
    finally:
        shutil.rmtree(str(work), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
