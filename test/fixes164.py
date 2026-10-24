#!/usr/bin/env python3
"""1.10.164: the bars on the Traffic overview's cards show every colour the
numbers beside them are written in.

    ./test/fixes164.py
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PASS = FAIL = 0


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


page = (HERE.parent / 'web' / 'index.php').read_text(encoding='utf-8')


def js_function(name):
    at = page.index('\nfunction %s(' % name) + 1
    return page[at:page.index('\n}', at) + 2]


print('\nOne bar of a card')
ok('every row\'s bar is drawn from all it holds', 'var bar = tSplitBar(r.by, fullest, order);' in page)
node = shutil.which('node')
if node:
    script = r'''
function el(tag, cls) { return {tag: tag, className: cls || '', style: {}, children: [],
  appendChild: function (c) { this.children.push(c); return c; }}; }
var T_ORDER = ['allow', 'deny', 'block', 'fail', 'info'];
var T_VERDICTS = {allow: {fill: 'g'}, deny: {fill: 'r'}, block: {fill: 'o'}, fail: {fill: 'v'},
                  info: {fill: 'm'}};
''' + js_function('tSplitBar') + r'''
function shape(by, top) {
  var bar = tSplitBar(by, top);
  var fill = bar.children[0];
  return fill ? {width: fill.style.width, min: fill.style.minWidth,
                 pieces: fill.children.map(function (p) { return p.style.background + p.style.flexGrow; })}
              : null;
}
console.log(JSON.stringify({
  mixed: shape({allow: 130, deny: 498831, info: 41298}, 540259),
  half: shape({deny: 50}, 100),
  tiny: shape({fail: 78, info: 2078}, 110698),
  none: shape({}, 10)
}));
'''
    got = json.loads(subprocess.run([node, '-e', script], capture_output=True, text=True,
                                    check=True).stdout)
    ok('a hundred let through beside half a million refused: both colours, and the rest',
       got['mixed']['pieces'], ['g130', 'r498831', 'm41298'])
    ok('...the whole length for the fullest row', got['mixed']['width'], '100%')
    ok('half the fullest row is half the bar', got['half']['width'], '50%')
    ok('a row too short to see is still wide enough for its two colours',
       (got['tiny']['pieces'], got['tiny']['min']), (['v78', 'm2078'], '9px'))
    ok('nothing at all is no bar', got['none'], None)
else:
    print('  (no node here: the page\'s own function is not run)')
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
