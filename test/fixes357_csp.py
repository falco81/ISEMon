#!/usr/bin/env python3
"""1.10.357: the card's check blocked by the dashboard's own policy. nginx-isemon.conf
sends a Content-Security-Policy of its own beside the page's, with img-src 'self'
data: - a browser holds to both, so the picture of the certificate's port was
blocked before it was sent (Chrome on Windows, an iPad: "the check got no answer
at all"). Root's helper lets any https picture through on that one line while
the card is watched (the page's own policy still names the one address), and
puts it back as it was when it is not.

    ./test/fixes357_csp.py
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'deploy'))
sys.path.insert(0, str(HERE.parent))
import isemon_web as w                               # noqa: E402

PASS = FAIL = 0


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


conf = (HERE.parent / 'deploy' / 'nginx-isemon.conf').read_text()
csp = [ln for ln in conf.split('\n') if 'Content-Security-Policy' in ln and 'add_header' in ln]
ok('the package\'s nginx sends a policy of its own', len(csp), 1)
ok('...with the line looked for', w.CSP_IMG_ISEMON in csp[0])
on, said = w.csp_for_watch(conf, True)
ok('watched: any https picture let through on that line', w.CSP_IMG_WATCH in on and said != '')
ok('...nothing else changed', on.replace(w.CSP_IMG_WATCH, w.CSP_IMG_ISEMON), conf)
ok('...asked again: nothing more', w.csp_for_watch(on, True), (on, ''))
off, said = w.csp_for_watch(on, False)
ok('not watched: as it was, byte for byte', (off, bool(said)), (conf, True))
ok('off and never on: nothing at all', w.csp_for_watch(conf, False), (conf, ''))
hand = conf.replace(w.CSP_IMG_ISEMON, "img-src 'self' data: blob:; connect-src 'self';")
ok('a policy changed by hand: never touched', w.csp_for_watch(hand, True), (hand, ''))
src = (HERE.parent / 'isemon.py').read_text()
ok('the request for root asked once more of a server already watched', "out['certlogin']['csp'] = 1" in src)
helper = (HERE.parent / 'deploy' / 'isemon_web.py').read_text()
ok('...and the helper puts it in with the certificate\'s port',
   "final, words = csp_for_watch(final, bool(cl.get('on') and cl.get('watch')))" in helper)
import isemon                                        # noqa: E402
import shutil, subprocess, tempfile, time            # noqa: E401,E402
folder = Path(tempfile.mkdtemp(prefix='isemon-358-'))
try:
    for k, v in dict(STATE_DIR=folder, DB_FILE=folder / 'c.db', BACKUP_DIR=folder / 'b',
                     DUMP_DIR=folder / 'd', RUN_DIR=folder, LOG_DIR=folder,
                     CONFIG_FILE=folder / 'config.json', _LOG_PATH=folder / 'c.log').items():
        setattr(isemon, k, v)
    isemon.CONFIG.clear()
    isemon.CONFIG.update(isemon.DEFAULTS)
    isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0, 'directory': 1, 'directory_host': 'dc.x',
                          'directory_base': 'DC=x,DC=y', 'certlogin': 1, 'certlogin_watch': 'grace'})
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
                    '-nodes', '-keyout', str(folder / 'c.key'), '-out', str(folder / 'c.pem'), '-days', '2',
                    '-subj', '/CN=c'], capture_output=True, check=True)
    store = isemon.Storage(isemon.DB_FILE)
    d = isemon.Daemon(store)
    d.add_user('falco', 'a-long-enough-password-1', 'fulladmin', by='test')
    print('1.10.358: a window of the card\'s, and F5')
    tok = store.new_session('falco', 'fulladmin', '1.2.3.4', 't', '')
    d.certlogin_watch_mark(tok, (folder / 'c.pem').read_text())
    ok('a check waiting on a window, the browser never proven: no word about it',
       (d.certlogin_card_gone(tok, 'waiting'), store.session(tok).get('card_ok')),
       ({'watched': False, 'gone': False}, None))
    store.session_card(tok, card_ok=time.time())
    got = d.certlogin_card_gone(tok, 'waiting')
    ok('...proven: the card out, the session waits', (got['watched'], got['gone']), (True, False))
    store.session_card(tok, card_out=time.time() - 7)
    ok('F5: the page told how long it has been out, by the server\'s clock',
       7 <= d.certlogin_watch_for(tok)['out_for'] <= 8)
    page = (HERE.parent / 'web' / 'index.php').read_text()
    ok('page: counted from that', 'CW.out = Date.now() - Math.max(0, conf.out_for || 0) * 1000;' in page)
    ok('page: the countdown behind a window of the card\'s after 4 s', "api('card-gone', {why: 'waiting'}" in page)
    ok('page: said to press OK, not Cancel', 'not Cancel. After Cancel the browser offers no card' in page)
finally:
    shutil.rmtree(str(folder), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
