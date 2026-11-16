#!/usr/bin/env python3
"""1.10.353 / 1.10.354: the card watched while signed in with it - the
daemon's half, as the kit card-removal-watch (otp 1.0.285) merged it.

Off by default and nothing changes. The state is kept in the session's own
row (card, card_seen, card_out): a restart forgets nothing. signout ends the
session at the first check without the card; grace waits, and the session
is held (HTTP 423, code card) while the card is out; another card ends it at
once; a page that stopped checking (an iPad asleep) is held, never ended for
it, until a check finds the card; the page's own word that the handshake
failed (card-gone) ends or holds only its own session. (Through nginx and
PHP: fixes341.)

    ./test/fixes353_cardwatch.py
"""
import json
import random
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import isemon                                        # noqa: E402

PASS = FAIL = 0
PORT = 21000 + random.randint(0, 3000)


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


def call(path, method='GET', payload=None, session=None):
    req = urllib.request.Request('http://127.0.0.1:%d%s' % (PORT, path),
                                 data=json.dumps(payload).encode() if payload is not None
                                 else None, method=method)
    req.add_header('X-Isemon-Token', isemon.API_TOKEN)
    if session:
        req.add_header('X-Isemon-Session', session)
    if payload is not None:
        req.add_header('Content-Type', 'application/json')
    try:
        with urllib.request.urlopen(req, timeout=60) as answer:
            return answer.status, json.loads(answer.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or '{}')


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
                     CONFIG_FILE=folder / 'config.json', _LOG_PATH=folder / 'c.log',
                     TOKEN_FILE=folder / 'tok').items():
        setattr(isemon, k, v)
    isemon.CONFIG.clear()
    isemon.CONFIG.update(isemon.DEFAULTS)
    isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0, 'directory': 1, 'directory_host': 'dc.x',
                          'directory_base': 'DC=corpnet,DC=loc', 'certlogin': 1, 'api_port': PORT})
    store = isemon.Storage(isemon.DB_FILE)
    d = isemon.Daemon(store)
    d.add_user('falco', 'a-long-enough-password-1', 'fulladmin', by='test')
    api = isemon.ApiServer(d, PORT)
    api.start()
    time.sleep(0.4)

    def session(with_card=True, proven=False):
        tok = store.new_session('falco', 'fulladmin', '192.0.2.1', 'test', '')
        if with_card:
            d.certlogin_watch_mark(tok, card)
            if proven:
                store.session_card(tok, card_ok=time.time())
        return tok

    def row(tok):
        return store.session(tok) or {}

    def events(like):
        return store.db.execute('SELECT COUNT(*) FROM events WHERE detail LIKE ?',
                                ('%' + like + '%',)).fetchone()[0]

    print('off by default')
    ok('defaults', (isemon.DEFAULTS['certlogin_watch'], isemon.DEFAULTS['certlogin_watch_s'],
                    isemon.DEFAULTS['certlogin_watch_grace_s']), ('off', 15, 30))
    tok = session(proven=True)
    ok('off: the page is told nothing', d.certlogin_watch_for(tok), None)
    ok('off: no card, nothing happens', (d.certlogin_alive(tok, '')['watched'],
                                         bool(d.who(tok))), (False, True))
    ok('off: whoami says null', call('/api/auth/whoami', session=tok)[1].get('certwatch'), None)
    ok('the fingerprint in the session\'s own row, never the certificate',
       (len(row(tok).get('card') or ''), 'BEGIN' in str(row(tok))), (64, False))
    ok('nothing in meta any more', bool(store.get_meta('certlogin_sessions')), False)

    print('signout')
    isemon.CONFIG['certlogin_watch'] = 'signout'
    w = d.certlogin_watch_for(tok)
    ok('the page is told the mode, the interval, the port', (w['mode'], w['every'], w['port'],
                                                             w['out'], w['stale']),
       ('signout', 15, 8443, False, False))
    ok('the card there: alive', d.certlogin_alive(tok, card)['alive'], True)
    ok('the card out: the session ends', (d.certlogin_alive(tok, '')['gone'], d.who(tok)),
       (True, None))
    ok('...said in Events', events('falco was signed out: the card they signed in with was taken out'), 1)
    tok = session(proven=True)
    ok('another card: ends at once', (d.certlogin_alive(tok, other)['gone'], d.who(tok)),
       (True, None))
    tok = session(proven=True)
    ok('the page: the handshake failed (card-gone) - ends', call('/api/auth/card-gone', 'POST', {},
                                                                session=tok)[1].get('gone'), True)
    ok('...signed out', d.who(tok), None)
    plain = session(with_card=False)
    ok('a session signed in with a password: never watched',
       (d.certlogin_watch_for(plain), d.certlogin_alive(plain, '')['watched'],
        call('/api/auth/card-gone', 'POST', {}, session=plain)[1].get('watched'), bool(d.who(plain))),
       (None, False, False, True))
    ok('card-gone without a session: refused', call('/api/auth/card-gone', 'POST', {})[0], 401)

    print('grace')
    isemon.CONFIG['certlogin_watch'] = 'grace'
    isemon.CONFIG['certlogin_watch_grace_s'] = 20
    tok = session(proven=True)
    got = d.certlogin_alive(tok, '')
    ok('the card out: waits, the time left said', (got['gone'], got['alive'], 18 <= got['grace_left'] <= 20),
       (False, False, True))
    ok('...kept in the row', bool(row(tok).get('card_out')), True)
    ok('...said in Events', events('falco: the card they signed in with is out - the session waits 20 s'), 1)
    st, body = call('/api/status', session=tok)
    ok('held: the pages answer nothing (423, code card)', (st, body.get('code')), (423, 'card'))
    st, body = call('/api/auth/whoami', session=tok)
    ok('...whoami still answers, the page told the card is out', (st, body['certwatch']['out']),
       (200, True))
    d2 = isemon.Daemon(store)
    ok('a restart of the daemon forgets nothing', d2.who(tok).get('card'), 'out')
    ok('back in time: alive again', d.certlogin_alive(tok, card)['alive'], True)
    ok('...the row cleared, said in Events', (row(tok).get('card_out'), events('is back')), (None, 1))
    ok('...the pages answer again', call('/api/status', session=tok)[0], 200)
    d.certlogin_alive(tok, '')
    store.session_card(tok, card_out=time.time() - 25)
    ok('out longer than the grace: ends', (d.certlogin_alive(tok, '')['gone'], d.who(tok)),
       (True, None))
    tok = session(proven=True)
    ok('card-gone in grace: holds', (call('/api/auth/card-gone', 'POST', {}, session=tok)[1].get('gone'),
                                     d.who(tok).get('card')), (False, 'out'))
    store.session_card(tok, card_out=time.time() - 3600)
    ok('the card out for long, nobody checking: ended by the server', d.who(tok), None)
    tok = session(proven=True)
    ok('another card in grace: ends at once too', d.certlogin_alive(tok, other)['gone'], True)

    print('a page asleep (an iPad locked) - held, not ended')
    for mode in ('signout', 'grace'):
        isemon.CONFIG['certlogin_watch'] = mode
        tok = session(proven=True)
        store.session_card(tok, card_seen=time.time() - 3600)
        me = d.who(tok)
        ok('%s: no check for an hour - still there, held' % mode, (bool(me), me and me.get('card')),
           (True, 'stale'))
        ok('...the pages answer nothing', call('/api/status', session=tok)[0], 423)
        ok('...the page told to check at once', call('/api/auth/whoami', session=tok)[1]
           ['certwatch']['stale'], True)
        ok('...the card found: goes on', (d.certlogin_alive(tok, card)['alive'], d.who(tok).get('card'),
                                          call('/api/status', session=tok)[0]), (True, '', 200))
    isemon.CONFIG['certlogin_watch'] = 'signout'
    tok = session(proven=True)
    store.session_card(tok, card_seen=time.time() - 3600)
    ok('asleep, then the card not there: a card taken out', (d.certlogin_alive(tok, '')['gone'],
                                                              d.who(tok)), (True, None))
    tok = session(proven=True)
    store.session_card(tok, card_seen=None)
    ok('switched on after the sign-in: watched from now', (d.who(tok).get('card'),
                                                           bool(row(tok).get('card_seen'))), ('', True))

    print('a browser that cannot be checked (1.10.355: an iPad)')
    isemon.CONFIG['certlogin_watch'] = 'signout'
    ok('default: allow', isemon.DEFAULTS['certlogin_watch_unable'], 'allow')
    tok = session()
    got = d.certlogin_alive(tok, '')
    ok('the first check without the card: not watched, not signed out',
       (got.get('unable'), got['gone'], bool(d.who(tok))), (True, False, True))
    ok('...said in Events, with why', events("cannot be checked in this browser - no certificate came"), 1)
    ok('...the page told nothing to watch', (d.certlogin_watch_for(tok),
                                             call('/api/auth/whoami', session=tok)[1].get('certwatch')),
       (None, None))
    ok('...never held either', (d.certlogin_alive(tok, '')['watched'], call('/api/status', session=tok)[0]),
       (False, 200))
    store.session_card(tok, card_seen=time.time() - 3600)
    ok('...nor when its page sleeps', d.who(tok).get('card'), '')
    tok = session()
    ok('no cookie came with the check, never found: not watched, why said',
       (call('/api/auth/card-gone', 'POST', {'why': 'nocookie'}, session=tok)[1].get('unable'),
        events('the browser sent no cookie with the check')), (True, 1))
    tok = session()
    ok('no answer at all, never found: not watched',
       call('/api/auth/card-gone', 'POST', {}, session=tok)[1].get('unable'), True)
    ok('...why said', events('the check got no answer at all'), 1)
    tok = session()
    ok('once found, the card proven in this browser', (d.certlogin_alive(tok, card)['alive'],
                                                        float(row(tok).get('card_ok') or 0) > 0),
       (True, True))
    ok('...then without it: a card taken out, as before', (d.certlogin_alive(tok, '')['gone'], d.who(tok)),
       (True, None))
    isemon.CONFIG['certlogin_watch_unable'] = 'signout'
    tok = session()
    ok('signout: never found - signed out as a card out', (d.certlogin_alive(tok, '')['gone'], d.who(tok)),
       (True, None))
    isemon.CONFIG['certlogin_watch_unable'] = 'allow'

    print('switched off')
    isemon.CONFIG['certlogin_watch'] = 'grace'
    tok = session()
    d.certlogin_alive(tok, '')
    isemon.CONFIG['certlogin'] = 0
    ok('certificate sign-in off: nothing watched, nothing held',
       (d.certlogin_watch_for(tok), bool(d.who(tok)), d.who(tok).get('card')), (None, True, ''))
    isemon.CONFIG['certlogin'] = 1
    isemon.CONFIG['certlogin_watch'] = 'off'
    ok('watching off: a card out before is not held', d.who(tok).get('card'), '')

    print('the request for root')
    d.certlogin_cas = lambda: [{'pem': card, 'sha256': 'x'}]
    d.certlogin_on = lambda: True
    r_off = d.webroot.request()
    ok('off: the request as before - no word of it', 'watch' in (r_off or {}).get('certlogin', {}),
       False)
    isemon.CONFIG['certlogin_watch'] = 'grace'
    r_on = d.webroot.request()
    ok('on: root is asked for it', r_on['certlogin'].get('watch'), True)
    ok('...a new request (the hash differs)', r_on['hash'] != r_off['hash'], True)

    print('the page')
    page = (HERE.parent / 'web' / 'index.php').read_text()
    papi = (HERE.parent / 'web' / 'isemon-api.php').read_text()
    helper = (HERE.parent / 'deploy' / 'isemon_web.py').read_text()
    ok('the check before the nonce of the sign-in', page.index("=== 'cert-alive'") <
       page.index("$try = (string) ($_GET['api'] ?? '') === 'cert-check';"))
    ok('the policy lets in the port only for a watched session',
       "$cwsrc = preg_match('/^[A-Za-z0-9.-]+$/', $cwh) ? \"https://$cwh:$cwp\" : 'https:';" in page and
       "is_array($me['certwatch'] ?? null)" in page)
    ok('whoami hands on numbers and words only', ("(int) ($cw['port'] ?? 0)" in papi,
                                                   "'stale' => !empty($cw['stale'])" in papi),
       (True, True))
    ok('nginx: no connection kept open, the check let through - only while watched',
       ("'    keepalive_timeout         0;\\n' if c.get('watch') else ''" in helper,
        "'login|check|alive' if c.get('watch') else 'login|check'" in helper), (True, True))
    ok('card-gone relayed', "'card-gone'    => '/api/auth/card-gone'," in page)
    for what, there in (
            ('one check for all the tabs', "var CW_SHARED = 'isemon.card.check';"),
            ('one check at a time', 'if (!c || CW.busy) return;'),
            ('a failed picture asked once more', 'if (w !== 3 && CW.misses < 2 && !CW.out) { certWatchNext(1500); return; }'),
            ('the pages told when the handshake failed, or no cookie came',
             "api('card-gone', {why: w === 3 ? 'nocookie' : 'nopicture'}, {quiet: true})"),
            ('a browser that cannot be checked: left alone', 'if (w === 4) { certWatchUnable(); return; }'),
            ('checked when the page wakes', "['visibilitychange', 'pageshow', 'focus', 'online']"),
            ('the first check soon', 'certWatchNext(conf.out || conf.stale ? 300 : 1500);'),
            ('the countdown every second', 'CW.tick = setInterval(draw, 1000);'),
            ('switched on later: learnt', "certWatchLater(d && d.certwatch)"),
            ('the host as it is (IPv6 keeps its brackets)', "'https://' + location.hostname + ':' + c.port"),
            ('a 423 checks at once', "if (r.status === 423 && data && data.code === 'card') {"),
            ('why as a word of the tab, never from the address', "sessionStorage.setItem('isemon.card.out', why)"),
            ('the sign-in page says it from that word', "sessionStorage.getItem('isemon.card.out')"),
            ('design B: the ring', "'Put the card back'")):
        ok('page: ' + what, there in page)
    ok('page: no reason put into the address any more', '?certsaid=\' + encodeURIComponent' in page,
       False)
finally:
    shutil.rmtree(str(folder), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
