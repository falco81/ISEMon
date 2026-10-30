#!/usr/bin/env python3
"""1.10.241: the popups.

- A click beside a popup closes nothing: only its own buttons, its cross and
  Escape do.
- A popup opened from a popup keeps the one underneath whole - what was
  typed, searched, paged and scrolled - and closing it brings that one back
  as it was left, as many deep as they go. The same popup drawn again (its
  answer arriving) is drawn in its own place; a button that closes its popup
  and opens another hands its place over; going to another tab closes them
  all.

When node and Playwright are here, the page itself is run in Chromium with a
stand-in for the dashboard's helpers; otherwise only the page's text is
looked at.

    ./test/fixes241.py
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
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
print('The page')
ok('no click beside the popup closes it',
   "if (e.target === $('modal')) closeModal()" in page, False)
ok('popups are kept underneath one another', 'var MODAL_STACK = [];' in page and
   'function modalPark()' in page and 'function modalUnpark()' in page)
ok('closing one brings the one underneath back', 'modalUnpark();\n    return;' in page)
ok('another tab closes them all', "if (!$('modal').hidden) closeAllModals();\n  TAB = name;" in page)
ok('a number of an opening never given twice', 'MODAL_GEN = ++MODAL_SEQ;' in page)

# The popup's own code, run in a browser, when one is here.
a = page.index('var MODAL_CLOSE = null;')
b = page.index('/* What icon a button deserves')
code = page[a:b]
node = shutil.which('node')
npm_root = ''
if node and shutil.which('npm'):
    npm_root = subprocess.run(['npm', 'root', '-g'], capture_output=True, text=True).stdout.strip()
have_pw = bool(npm_root) and (Path(npm_root) / 'playwright').is_dir()
if not (node and have_pw):
    print('\n  (no node with Playwright here: the popups are not run)')
else:
    print('\nThe popups, run')
    work = Path(tempfile.mkdtemp(prefix='isemon-241-'))
    html = ('<!doctype html><html><body><div class="modal" id="modal" hidden><div class="box" '
            'id="modal-box"><div class="head"><h3 id="modal-title"></h3><button id="modal-x">'
            '</button></div><div class="body" id="modal-body"></div><div class="foot" '
            'id="modal-foot"></div></div></div><script>'
            'function $(i){return document.getElementById(i);}'
            'function el(t,c,x){var n=document.createElement(t);if(c)n.className=c;'
            'if(x!==undefined)n.textContent=x;return n;}'
            'function clear(n){while(n.firstChild)n.removeChild(n.firstChild);}'
            'function setButtonIcon(){} var ADMIN=true;'
            'function iconForWords(){return "";}'
            + code.replace('</script>', '') + '</script></body></html>')
    (work / 'p.html').write_text(html)
    (work / 't.js').write_text(r'''
const { chromium } = require('playwright');
(async () => {
  const b = await chromium.launch();
  const p = await b.newPage();
  const errs = [];
  p.on('pageerror', e => errs.push(e.message));
  await p.goto('file://' + process.argv[2]);
  const r = await p.evaluate(async () => {
    const out = {};
    modal('A', function (body) { var i = el('input'); i.id = 'ia'; body.appendChild(i); },
      [{words: 'B', go: function () {
        modal('B', function (body) { var i = el('input'); i.id = 'ib'; body.appendChild(i); },
          [{words: 'C', go: function () { modal('C', function () {}); }}, {words: 'x', close: true}]);
      }}, {words: 'x', close: true}]);
    $('ia').value = 'a';
    document.querySelectorAll('#modal-foot button')[0].click();
    $('ib').value = 'b';
    document.querySelectorAll('#modal-foot button')[0].click();
    out.top = $('modal-title').textContent;
    $('modal').dispatchEvent(new MouseEvent('click', {bubbles: true}));
    out.beside = $('modal').hidden ? 'closed' : $('modal-title').textContent;
    closeModal();
    out.one = $('modal-title').textContent + '/' + $('ib').value;
    document.dispatchEvent(new KeyboardEvent('keydown', {key: 'Escape'}));
    out.two = $('modal-title').textContent + '/' + $('ia').value;
    closeModal();
    out.gone = $('modal').hidden;
    modal('L', function () {}, [{words: 'do', close: true, go: function () { modal('W', function () {}); }}]);
    document.querySelectorAll('#modal-foot button')[0].click();
    out.handed = $('modal-title').textContent + '/' + MODAL_STACK.length;
    closeModal();
    modal('Q', function () {});
    var t = modalTicket();
    if (modalStill(t)) modal('Q · answered', function () {});
    out.redrawn = $('modal-title').textContent + '/' + MODAL_STACK.length;
    await new Promise(r => setTimeout(r, 10));
    modal('Child', function () {});
    out.child = MODAL_STACK.length;
    closeAllModals();
    out.all = $('modal').hidden && MODAL_STACK.length === 0;
    return out;
  });
  console.log(JSON.stringify({r: r, errs: errs}));
  await b.close();
})();
''')
    got = subprocess.run([node, str(work / 't.js'), str(work / 'p.html')], capture_output=True,
                         text=True, timeout=120, env=dict(os.environ, NODE_PATH=npm_root))
    try:
        res = json.loads(got.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        res = {'r': {}, 'errs': [got.stderr[-400:]]}
    r = res['r']
    ok('no error on the page', res['errs'], [])
    ok('three deep', r.get('top'), 'C')
    ok('a click beside it closes nothing', r.get('beside'), 'C')
    ok('closed: the one underneath, as it was left', r.get('one'), 'B/b')
    ok('...and the one under that (Escape)', r.get('two'), 'A/a')
    ok('the last closed: none left', r.get('gone'), True)
    ok('a button that closes its popup and opens another hands its place over',
       r.get('handed'), 'W/0')
    ok('an answer drawn into its popup: in its own place', r.get('redrawn'), 'Q · answered/0')
    ok('...and a popup opened from it afterwards keeps it underneath', r.get('child'), 1)
    ok('all closed at once', r.get('all'), True)
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
