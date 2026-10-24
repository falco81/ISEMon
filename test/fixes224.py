#!/usr/bin/env python3
"""1.10.224: "What root did last" is not shown on the firewall card either
(nor anywhere else on the page); a failure is still shown with what root said.

    ./test/fixes224.py
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
print('\nThe page')
ok('no "What root did last" anywhere', 'What root did last' not in page)
ok('a failure still shows what root said', "'What root said:'" in page)
ok('...with a way to try again', "action: 'retry'" in page)
ok('the firewall card still shows its state line',
   "body.appendChild(wrRootLine(d.root, 'the firewall or the lists'))" in page)
import re
v = re.search(r"__version__ = '1\.10\.(\d+)'", (ROOT / 'isemon.py').read_text(encoding='utf-8'))
ok('the version is 1.10.224 or later', bool(v) and int(v.group(1)) >= 224)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
