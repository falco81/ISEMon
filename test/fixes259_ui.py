#!/usr/bin/env python3
"""1.10.259: a pane opened by its address (F5 on #settings/acme) is drawn
whole - its code may come in a later block of the page than the code that
opens it - and the menu is scrolled to its button; a setting that is not in
use cannot be typed into, as otp has it. Checked in the page itself, and in
a browser when playwright is there.

    ./test/fixes259_ui.py
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


page = (ROOT / 'web' / 'index.php').read_text()
last = page[page.rindex('<script'):page.rindex('</script>')]
ok('once every script is read, the pane the address opened is shown again',
   "showPane(PANE, true);" in last and 'setTimeout(function () {' in last)
ok('...after the block with Automatic certificates\' code',
   page.index('function loadAcme()') < page.rindex("showPane(PANE, true);"))
ok('the menu scrolled to the pane\'s button, on every showing',
   ('function navShowOn()' in page, '  navShowOn();\n  Array.prototype.forEach.call(document.querySelectorAll(\'.ctl-pane\')'
    in page), (True, True))
i = page.index('function applyOnlyWhen()')
body = page[i:page.index('\nfunction ', i + 10)]
ok('a setting not in use: its boxes and choices disabled',
   "c.disabled = true; c.dataset.asleepOff = '1';" in body)
ok('...and given back only what that switched off',
   "else if (live && c.dataset.asleepOff) { c.disabled = false;" in body)
ok('...the switch of one not in use cannot be clicked', '.set-item.asleep .sw{pointer-events:none}' in page)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
