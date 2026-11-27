#!/usr/bin/env python3
"""1.10.382: every search box offers its fields only when asked (Ctrl+Space,
or its funnel), has a clear and a filter button inside it, and whatever was
pressed to open a popup or a page is already in that box: an address as
`ip:`, a person as `user:` / `name:`, an account as `account:`.

    ./test/fixes382_filters.py
"""
import subprocess
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


def body(name):
    i = page.index('function %s(' % name)
    return page[i:page.index('\nfunction ', i + 10)]


print('Offered only when asked')
qs = body('qSuggest')
ok('nothing offered on a focus or a click', ("input.addEventListener('click'" not in qs,
                                              "if (!st.armed) { close(); return; }" in qs),
   (True, True))
ok('Ctrl+Space or the funnel opens it', 'if (qsAsked(e)) {' in qs and 'searchTools(input, me.arm);' in qs)
ok('...and so on the Traffic page', "if (!TSUG.armed) { tSuggestClose(); return; }" in page
   and "searchTools($('t-q'), tSuggestArm);" in page
   and "$('t-q').addEventListener('click'" not in page)
ok('a clear and a filter button inside the box', all(x in body('searchTools') for x in (
    "iconMarkup('close', 14)", "iconMarkup('funnel', 15)", "input.value = '';")))
ok('...and a clear one in the boxes that offer nothing', "searchTools($('ctl-find'));" in page
   and "searchTools($('findinput'));" in page)

print('Opened on something, filtered on it')
ok('an address\'s own lists start with ip: and the address',
   page.count("scope: {term: qTerm('ip', d.ip), params: {ip: d.ip}},") == 2)
ok('...asked as the list\'s own parameter while it is in the box, and not once it is gone',
   "if (asked.on) params[k] = scope.params[k]; else delete params[k];" in page)
ok('a name\'s lists start with name:', page.count("qTerm('name', name)") == 2)
ok('...and its page opens on user:', "q: qTerm('user', name), door: r.kind === 'judged'" in page)
ok('a pressed row of a card: the popup and the page both on it',
   "peekFailedRows(answer.rows, 'peek-door', ovListTerm(filter, said))" in page
   and "q: ovPageTerm(filter, said), door: d.door," in page)
ok('the domain popups open the events on that account', page.count(
    "a25Events(qTerm('account', ") == 2)
ok('a person found in Find is asked for exactly', page.count('personTerm(') >= 5)
ok('an address chip asks for the address exactly', "var q = d.q || qTerm('ip', ip);" in page)
ok('a list opened again forgets what was typed in the last one',
   "if (prefill !== undefined) { view.q = ''; view.page = 0; view.cc = ''; }" in page)

print('qTerm')
code = body('qTerm') + '''
console.log(JSON.stringify([qTerm('ip', '10.1.2.3'), qTerm('user', 'Jan Novak'),
  qTerm('user', ''), qTerm('ip', '2001:db8::1')]));'''
r = subprocess.run(['node', '-e', code], capture_output=True, text=True)
ok('as the boxes read it', r.stdout.strip(),
   '["ip:10.1.2.3","user:\\"Jan Novak\\"","","ip:2001:db8::1"]')

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
