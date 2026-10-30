#!/usr/bin/env python3
"""1.10.243: the page after an upgrade from the pages.

"Load it again" loaded the page in the seconds after the new version had
started, and the page's first question waited on a daemon still starting:
nothing was drawn until F5. Now the button waits until the new version
answers - its version, and its status - and the page, until its first
answer, asks again after fifteen seconds rather than a minute.

    ./test/fixes243.py
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PASS = FAIL = 0


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


page = (ROOT / 'web' / 'index.php').read_text(encoding='utf-8')
a = page.index("var a = cmdButton('Load it again'")
btn = page[a:a + 1600]
ok('Load it again does not reload at once', "a.onclick = function () { location.reload(); };"
   in page, False)
ok('...it asks the new version first', "api('upgrade', undefined, {quiet: true})" in btn)
ok('...and its status, what the page draws from', "api('status&logs=0', undefined, {quiet: true})"
   in btn)
ok('...for two minutes at most, then loads anyway', 'Date.now() + 120000' in btn and
   btn.count('location.reload()') >= 2)
ok('until the first answer the page asks again after 15 s',
   'Date.now() - TICK_BUSY < (LAST_OK ? 65000 : 15000)' in page)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
