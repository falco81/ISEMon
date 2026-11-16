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
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
