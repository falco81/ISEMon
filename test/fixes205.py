#!/usr/bin/env python3
"""1.10.205: the public lists' switches wait for Save the changes, as every
other setting does, instead of each saving itself the moment it is flipped.

    ./test/fixes205.py
"""
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
page = (HERE.parent / 'web' / 'index.php').read_text(encoding='utf-8')
PASS = FAIL = 0


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


feeds = page[page.index('function drawFeeds(feeds) {'):page.index("$('feeds-fetch').onclick")]
print('\nThe public lists')
ok('a switch saves nothing by itself', "api('settings'" in feeds, False)
ok('...it marks the change for Save the changes', 'input.onchange = feedsMarkDirty;' in feeds)
ok('...counted with the rest', 'if (now !== FEEDS_SAVED) DIRTY.feeds = now; else delete DIRTY.feeds;'
   in page and 'markDirtyCount();' in page[page.index('function feedsMarkDirty'):])
ok('...flipped back is no change', "one.checked !== (one.dataset.was === '1')" in page)
ok('...and a card drawn again keeps what was flipped and not saved',
   "var pending = ('feeds' in DIRTY)" in feeds)
ok('the card says how it is saved', '<b>Save the changes</b>' in page
   and 'A list switched on or off here is saved with' in page)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
