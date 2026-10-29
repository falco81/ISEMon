#!/usr/bin/env python3
"""1.10.169: a card of the Traffic tab puts first, in its bars, its numbers
and its words, what it is about - the refused on the refused cards.

    ./test/fixes169.py
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


def js_var(name):
    at = page.index('\nvar %s = ' % name) + 1
    return page[at:page.index('\n};', at) + 3] if page[at:].startswith('var %s = {' % name) \
        else page[at:page.index(';\n', at) + 2]


print('\nThe order of a card')
node = shutil.which('node')
if not node:
    print('  (no node here)')
else:
    tops = page[page.index('\nvar T_TOPS = [') + 1:]
    tops = tops[:tops.index('\n];\n') + 4]
    script = r'''
var T_SESSIONS_ONLY = '';
function tQuote(v) { return v; }
var T_VERDICTS = {allow: {fill: 'g'}, deny: {fill: 'r'}, block: {fill: 'o'}, fail: {fill: 'v'},
                  info: {fill: 'd'}};
function num(n) { return String(n); }
var made = [];
function el(tag, cls, text) {
  var e = {tag: tag, cls: cls, text: text, children: [], style: {}, classList: {add: function () {}},
           appendChild: function (c) { this.children.push(c); return c; }};
  return e;
}
document = {createTextNode: function (t) { return {text: t}; }};
''' + js_var('T_ORDER') + tops + js_function('tCardOrder') + js_function('tSplitBar') \
        + js_function('tByDots') + r'''
function card(dim, part) { return T_TOPS.filter(function (t) { return t.dim === dim && t.part === part; })[0]; }
var rows = [{by: {allow: 421, deny: 4421}}, {by: {allow: 2762, deny: 4250}}];
var out = {};
out.refused = tCardOrder(card('src', 'refused'), rows);
out.port = tCardOrder(card('port', 'refused'), [{by: {allow: 369693, deny: 11959}}]);
out.knocking = tCardOrder(card('scc', 'refused'), rows);
out.talks = tCardOrder(card('src', 'busiest'), [{by: {allow: 313396}}, {by: {allow: 78902, deny: 2}}]);
out.drop = tCardOrder(card('drop', 'busiest'), [{by: {deny: 5, info: 1}}]);
out.s2swhy = tCardOrder(card('s2swhy', 'busiest'), [{by: {fail: 5, info: 9}}]);
out.ips = tCardOrder(card('ips', 'busiest'), [{by: {block: 50, info: 3}}, {by: {allow: 2}}]);
var bar = tSplitBar({allow: 421, deny: 4421}, 7000, out.refused);
out.bar = bar.children[0].children.map(function (c) { return c.style.background; });
out.dots = tByDots({allow: 421, deny: 4421}, out.refused).children.map(function (c) {
  return c.children[1].text; });
out.plain = tSplitBar({allow: 1, deny: 2}, 3).children[0].children.map(function (c) {
  return c.style.background; });
console.log(JSON.stringify(out));
'''
    got = json.loads(subprocess.run([node, '-e', script], capture_output=True, text=True,
                                    check=True).stdout)
    ok('Refused, from: the refused first', got['refused'][:3], ['deny', 'block', 'fail'])
    ok('Refused, at which port: the refused first, though most were let through',
       got['port'][:3], ['deny', 'block', 'fail'])
    ok('Countries knocking: the refused first', got['knocking'][0], 'deny')
    ok('Who talks the most: the let through first', got['talks'][0], 'allow')
    ok('Dropped on the way: the dropped first', got['drop'][:2], ['deny', 'block'])
    ok('Why tunnels fail: the failures first', got['s2swhy'][0], 'fail')
    ok('Intrusions (IPS): the blocked first', got['ips'][0], 'block')
    ok('a card about none of them keeps the usual order',
       tuple(got['talks']), ('allow', 'deny', 'block', 'fail', 'info'))
    ok('every verdict is still in the order, once',
       all(sorted(v) == sorted(['allow', 'deny', 'block', 'fail', 'info'])
           for k, v in got.items() if k not in ('bar', 'dots', 'plain')))
    ok('the bar of a refused row begins red', got['bar'], ['r', 'g'])
    ok('and its numbers with the refused', got['dots'], ['4421', '421'])
    ok('a bar asked for no order keeps the usual one', got['plain'], ['g', 'r'])

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
