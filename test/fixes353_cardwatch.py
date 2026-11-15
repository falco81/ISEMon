#!/usr/bin/env python3
"""1.10.353: the card watched while signed in with it. The daemon's half:
off by default and nothing changes; signout ends the session at the first
check without the card; grace waits; another card ends it at once; a page
that stops checking ends it on the server too; a session not signed in with
a certificate is never touched. The page's policy lets the check's picture
in only for a watched session. (Through nginx and PHP: fixes341.)

    ./test/fixes353_cardwatch.py
"""
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
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


folder = Path(tempfile.mkdtemp(prefix='isemon-353-'))
try:
    def cert(cn):
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt',
                        'ec_paramgen_curve:P-256', '-nodes', '-keyout', str(folder / (cn + '.key')),
                        '-out', str(folder / (cn + '.pem')), '-days', '2', '-subj', '/CN=' + cn],
                       capture_output=True, check=True)
        return (folder / (cn + '.pem')).read_text()
    card, other = cert('card-one'), cert('card-two')
    for k, v in dict(STATE_DIR=folder, DB_FILE=folder / 'c.db', BACKUP_DIR=folder / 'b',
                     DUMP_DIR=folder / 'd', RUN_DIR=folder, LOG_DIR=folder,
                     CONFIG_FILE=folder / 'config.json', _LOG_PATH=folder / 'c.log').items():
        setattr(isemon, k, v)
    isemon.CONFIG.clear()
    isemon.CONFIG.update(isemon.DEFAULTS)
    isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0, 'directory': 1, 'directory_host': 'dc.x',
                          'directory_base': 'DC=corpnet,DC=loc', 'certlogin': 1})
    store = isemon.Storage(isemon.DB_FILE)
    d = isemon.Daemon(store)
    d.add_user('falco', 'a-long-enough-password-1', 'fulladmin', by='test')

    def session(with_card=True):
        tok = store.new_session('falco', 'fulladmin', '192.0.2.1', 'test', '')
        if with_card:
            d.certlogin_watch_mark(tok, card)
        return tok

    print('off by default')
    ok('defaults', (isemon.DEFAULTS['certlogin_watch'], isemon.DEFAULTS['certlogin_watch_s'],
                    isemon.DEFAULTS['certlogin_watch_grace_s']), ('off', 15, 30))
    tok = session()
    ok('off: the page is told nothing', d.certlogin_watch_for(tok), None)
    ok('off: no card, nothing happens', (d.certlogin_alive(tok, '')['watched'],
                                         bool(d.who(tok))), (False, True))
    ok('only the fingerprint is kept, never the certificate',
       'BEGIN CERTIFICATE' not in (store.get_meta('certlogin_sessions') or ''), True)

    print('signout')
    isemon.CONFIG['certlogin_watch'] = 'signout'
    w = d.certlogin_watch_for(tok)
    ok('the page is told the mode, the interval and the port', (w['mode'], w['every'], w['port']),
       ('signout', 15, 8443))
    ok('the card there: alive', d.certlogin_alive(tok, card)['alive'], True)
    ok('the card out: the session ends', (d.certlogin_alive(tok, '')['gone'], d.who(tok)),
       (True, None))
    ok('...said in Events', store.db.execute(
        "SELECT COUNT(*) FROM events WHERE detail LIKE '%falco was signed out: the card%'"
    ).fetchone()[0], 1)
    tok = session()
    ok('another card: ends at once', (d.certlogin_alive(tok, other)['gone'], d.who(tok)),
       (True, None))
    plain = session(with_card=False)
    ok('a session signed in with a password: never watched',
       (d.certlogin_watch_for(plain), d.certlogin_alive(plain, '')['watched'], bool(d.who(plain))),
       (None, False, True))

    print('grace')
    isemon.CONFIG['certlogin_watch'] = 'grace'
    isemon.CONFIG['certlogin_watch_grace_s'] = 20
    tok = session()
    got = d.certlogin_alive(tok, '')
    ok('the card out: waits, the time left said', (got['gone'], got['alive'], 18 <= got['grace_left'] <= 20),
       (False, False, True))
    ok('...still signed in', bool(d.who(tok)), True)
    ok('back in time: alive again', d.certlogin_alive(tok, card)['alive'], True)
    d.certlogin_alive(tok, '')
    d._CL_WATCH[d._cols_key(tok)]['gone'] -= 25
    ok('out longer than the grace: ends', (d.certlogin_alive(tok, '')['gone'], d.who(tok)),
       (True, None))
    tok = session()
    ok('another card in grace: ends at once too', d.certlogin_alive(tok, other)['gone'], True)

    print('the server\'s half')
    isemon.CONFIG['certlogin_watch'] = 'signout'
    tok = session()
    ok('checked lately: stays', bool(d.who(tok)), True)
    d._CL_WATCH[d._cols_key(tok)]['seen'] -= 3600
    ok('a page that stopped checking: ends on the server', d.who(tok), None)
    tok = session()
    d._CL_WATCH.clear()                      # as after a restart of the daemon
    ok('after a restart: counted from now, not ended', bool(d.who(tok)), True)
    isemon.CONFIG['certlogin'] = 0
    tok2 = session()
    d._CL_WATCH[d._cols_key(tok2)]['seen'] -= 3600
    ok('certificate sign-in switched off: nothing watched', (d.certlogin_watch_for(tok2),
                                                             bool(d.who(tok2))), (None, True))
    isemon.CONFIG['certlogin'] = 1

    print('the page')
    page = (HERE.parent / 'web' / 'index.php').read_text()
    api = (HERE.parent / 'web' / 'isemon-api.php').read_text()
    helper = (HERE.parent / 'deploy' / 'isemon_web.py').read_text()
    ok('the check before the nonce of the sign-in', page.index("=== 'cert-alive'") <
       page.index("$try = (string) ($_GET['api'] ?? '') === 'cert-check';"))
    ok('the policy lets in the port only for a watched session',
       "img-src 'self' data: https://$cwh:$cwp;" in page and
       "is_array($me['certwatch'] ?? null)" in page)
    ok('whoami hands on numbers and a word only', "(int) ($cw['port'] ?? 0)" in api)
    ok('nginx: no connection kept open, the check let through - only while watched',
       ("'    keepalive_timeout         0;\\n' if c.get('watch') else ''" in helper,
        "'login|check|alive' if c.get('watch') else 'login|check'" in helper), (True, True))
    ok('the page starts it, counts down and signs out', all(s in page for s in (
        'certWatchStart(ME.certwatch)', "'The card is out'", "api('logout', {})")))
    print('the request for root')
    isemon.CONFIG['certlogin_watch'] = 'off'
    d.certlogin_cas = lambda: [{'pem': card, 'sha256': 'x'}]
    d.certlogin_on = lambda: True
    r_off = d.webroot.request()
    ok('off: the request as before - no word of it', 'watch' in (r_off or {}).get('certlogin', {}), False)
    isemon.CONFIG['certlogin_watch'] = 'grace'
    r_on = d.webroot.request()
    ok('on: root is asked for it', r_on['certlogin'].get('watch'), True)
    ok('...a new request (the hash differs)', r_on['hash'] != r_off['hash'], True)
finally:
    shutil.rmtree(str(folder), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
