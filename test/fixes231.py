#!/usr/bin/env python3
"""1.10.231: Upgrades - From the web picks which version when several newer
ones are there; with one, nothing changes on the page. The page's own logic is
run in node where node is on the machine.

    ./test/fixes231.py
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
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
a = page.index('function drawUpWeb(d) {')
b = page.index('function drawUpgrade(d) {', a)
block = page[a:b]
ok('the list is drawn only when more than one is newer', 'if (newer.length > 1) {' in block)
ok('...the newest chosen unless another is', 'UP.pick = o.newest.version' in block)
ok('both buttons go by what is chosen', block.count('version: c.version') == 1 and
   'version: chosen().version' in block)
node = shutil.which('node')
if node:
    js = block[block.index('function upVer'):]
    code = js + '''
var a = upVer('1.10.230'), b = upVer('1.10.99'), c = upVer('1.10.230.1');
console.log(JSON.stringify([upCmp(a, b), upCmp(b, a), upCmp(a, a), upCmp(c, a)]));
'''
    got = subprocess.run([node, '-e', code], capture_output=True, text=True)
    ok('versions compared as numbers, not as words', json.loads(got.stdout or 'null'),
       [1, -1, 0, 1])
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
