#!/usr/bin/env python3
"""1.10.295: what the second round of review found, fixed.

- A dual certificate: the ECDSA twin must hold the names of the RSA one, on
  an upload and from acme push - browsers that speak ECDSA are given it; and
  its own root is kept for when it is downloaded.
- Counting up to a ban: a range is refused rather than said back to nought.
- A certificate ZIP with a damaged entry is said, not a 500.
- The password made for a database is shown once, to whoever moved it.
- Signing in: a burst of wrong passwords for a name from elsewhere no longer
  keeps it out from an address it signed in from before.
- The page: the session cookie is __Host- on TLS, a GET from another page
  of the site is refused, a record's words cannot put tags into a help
  panel, a country that is not two letters makes no flag address, the
  command to copy is quoted for the shell, the translator never takes a
  record's `<b>` for the page's.

    ./test/fixes295_audit.py
"""
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
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


def make(kind, name='isemon.example.cz', days=60):
    d = tempfile.mkdtemp(prefix='isemon-295-c-')
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
        return open(os.path.join(d, 'c')).read(), open(key).read()
    finally:
        shutil.rmtree(d, ignore_errors=True)


work = Path(tempfile.mkdtemp(prefix='isemon-295-'))
try:
    state = work / 'state'
    state.mkdir()
    for k, v in dict(STATE_DIR=state, DB_FILE=state / 'd.db', BACKUP_DIR=state / 'b',
                     DUMP_DIR=state / 'dumps', RUN_DIR=state, LOG_DIR=state,
                     CONFIG_FILE=state / 'config.json', _LOG_PATH=state / 'd.log',
                     TOKEN_FILE=state / 'token').items():
        setattr(isemon, k, v)
    isemon.CONFIG.clear()
    isemon.CONFIG.update(isemon.DEFAULTS)
    isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0})
    (state / 'config.json').write_text(json.dumps({'db_engine': 'sqlite'}))
    store = isemon.Storage(isemon.DB_FILE)
    daemon = isemon.Daemon(store)
    wr = daemon.webroot

    print('A dual certificate')
    rc, rk = make('rsa')
    ec_other, ek_other = make('ec', 'other.example.org')
    try:
        wr.tls_do({'action': 'upload', 'pem': [rc, rk, ec_other, ek_other]}, by='boss')
        ok('an ECDSA twin of another name: refused', False)
    except isemon.WebRootError as e:
        ok('an ECDSA twin of another name: refused, and said why',
           'does not hold isemon.example.cz' in str(e))
    ec, ek = make('ec')
    got = wr.tls_do({'action': 'upload', 'pem': [rc, rk, ec, ek]}, by='boss')
    tls = wr.tls_conf()
    ok('...one of the same name: taken, side by side', (bool(tls.get('cert2')),
                                                        'root2' in tls), (True, True))
    ok('...and the names are told apart as the browser does',
       (isemon.twin_lacks({'names': ['a.cz', 'b.cz']}, {'names': ['*.cz']}),
        isemon.twin_lacks({'names': ['a.cz']}, {'names': ['b.cz'], 'cn': 'a.cz'})), ([], []))
    src = (ROOT / 'isemon.py').read_text()
    a = src.index('def push_install(')
    body = src[a:a + 4000]
    ok('acme push: the twin\'s names checked, and exactly one RSA and one ECDSA',
       ("twin_lacks(main['facts'], alt['facts'])" in body,
        "sorted([alt['kind'][:2], main['kind'][:2]]) != ['ec', 'rs']" in body), (True, True))

    print('\nA damaged ZIP')
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr('a.pem', '-----BEGIN CERTIFICATE-----\n' + 'A' * 4000)
    raw = bytearray(buf.getvalue())
    for i in range(60, 120):
        raw[i] ^= 0x5a
    try:
        isemon.cert_zip_entries(bytes(raw))
        ok('a damaged entry: said', False)
    except isemon.WebRootError as e:
        ok('a damaged entry: said, not a 500', 'could not be read' in str(e) or 'ZIP' in str(e))
    except Exception as e:                            # noqa: BLE001
        ok('a damaged entry: said, not a 500 (%s)' % type(e).__name__, False)

    print('\nSigning in')
    daemon.add_user('boss', 'a-long-enough-password', 'fulladmin', by='test')
    daemon.login('boss', 'a-long-enough-password', ip='10.0.0.5')
    for n in range(8):
        for i in range(isemon.Daemon.LOGIN_NAME_TIMES * 5 // 8 + 1):
            try:
                daemon.login('boss', 'wrong', ip='192.0.2.%d' % (n * 10 + i))
            except Exception:                           # noqa: BLE001
                pass
    try:
        daemon.login('boss', 'a-long-enough-password', ip='192.0.2.250')
        ok('from a new address, after a burst for the name: still kept out', False)
    except Exception as e:                              # noqa: BLE001
        ok('from a new address, after a burst for the name: still kept out',
           'too many' in str(e))
    try:
        got = daemon.login('boss', 'a-long-enough-password', ip='10.0.0.5')
        ok('...from the address it signed in from before: let in', bool(got))
    except Exception as e:                              # noqa: BLE001
        ok('...from the address it signed in from before: let in (%s)' % e, False)

    print('\nThe page')
    api_php = (ROOT / 'web' / 'isemon-api.php').read_text()
    ok('the session cookie is __Host- on TLS',
       "isemon_https() ? '__Host-' . ISEMON_COOKIE : ISEMON_COOKIE" in api_php)
    page = (ROOT / 'web' / 'index.php').read_text()
    ok('a GET from another page of the site, or another site, refused',
       "if ($from === 'cross-site' || $from === 'same-site') {" in page)
    ok('a record\'s words in a help panel: no tag, no line break of their own',
       ".replace(/[\\r\\n]+/g, ' ');" in page and "'<b>' + wordsIn(c.user) + '</b> from '" in page)
    ok('a country of not two letters: no flag address',
       "if (!/^[A-Z]{2}$/.test(two)) {" in page)
    ok('the command to copy, quoted for the shell', "shQuote(wordsIn(u.name))" in page)
    ok('the translator never takes a record\'s <b> for the page\'s',
       "if (/[<>]/.test(k.nodeValue)) return '';" in page)
    ok('a name escaped once, not twice, in a help panel',
       ("'What <b>' + htmlText(u.name)" in page, "'The password for <b>' + htmlText(u.name)" in page),
       (False, False))
    php = shutil.which('php')
    if php:
        out = subprocess.run([php, '-r', 'include "%s"; $_SERVER["HTTPS"] = "on"; echo '
                              'isemon_cookie_name(), "|"; $_SERVER["HTTPS"] = "off"; '
                              'echo isemon_cookie_name();' % (ROOT / 'web' / 'isemon-api.php')],
                             capture_output=True, text=True).stdout.strip()
        ok('...its name on TLS and without', out.split('\n')[-1][-38:],
           '__Host-isemon_session|isemon_session')
finally:
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
