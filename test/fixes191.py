#!/usr/bin/env python3
"""1.10.191: the published list for an OPNsense with a user name and a
password, as for a FortiGate; a pfSense still the key in the URL.

    ./test/fixes191.py
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
page = (HERE.parent / 'web' / 'index.php').read_text(encoding='utf-8')
source = (HERE.parent / 'isemon.py').read_text(encoding='utf-8')
PASS = FAIL = 0


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


opn = page[page.index('function guideOpnsenseFeed'):page.index('function guidePfsenseFeed')]
pf = page[page.index('function guidePfsenseFeed'):page.index('function guideScript')]
ok('the OPNsense guide gives the user name and the password with basic chosen',
   ("var basic = g.auth === 'basic';" in opn, '<b>Authentication:</b> Basic' in opn,
    "-u \\'' + g.user + ':PASSWORD\\' '" in opn), (True, True, True))
ok('...and does not call basic refused there', 'guideFeedAuth(body, g, \'OPNsense\')' in opn
   and '} else {\n    guideFeedAuth' in opn, True)
ok('the pfSense guide still says basic is refused', "guideFeedAuth(body, g, 'pfSense');" in pf,
   True)
ok('the setting says which firewalls send a password',
   'and so does a recent OPNsense' in source, True)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
