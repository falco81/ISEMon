#!/usr/bin/env python3
"""1.10.215: a MikroTik's API password shown and kept the way every other
password in Settings is - its dots and its last two letters."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))
sys.argv = ['isemon']
import isemon  # noqa: E402

PASS = FAIL = 0


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    ' + what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


sealed = isemon.seal_secret('choose-a-long-one')
rows = [{'name': 'gw', 'type': 'routeros', 'path': '/x',
         'api': {'on': 1, 'host': 'gw', 'password': sealed}}]
shown = isemon.rosapi_masked(rows)[0]['api']
print('\nShown')
ok('as every password in Settings: its dots and its last two letters',
   (shown['password'], shown['password_set']),
   (isemon.secret_shown('choose-a-long-one'), True))
ok('...and nothing of a row with none', isemon.rosapi_masked(
    [{'name': 'x', 'type': 'routeros', 'api': {'password': ''}}])[0]['api']['password'], '')
print('\nKept')
kept = isemon.rosapi_kept_passwords(
    [{'name': 'gw', 'api': {'password': shown['password']}},
     {'name': 'gw', 'api': {'password': ''}},
     {'name': 'gw', 'api': {'password': 'a-new-one'}}],
    [{'name': 'gw', 'api': {'password': sealed}}])
ok('left as it was shown, or emptied: the one that is set',
   (kept[0]['api']['password'], kept[1]['api']['password']), (sealed, sealed))
ok('...typed over: the new one, sealed',
   isemon.unseal_secret(kept[2]['api']['password']), 'a-new-one')
page = (HERE / 'web' / 'index.php').read_text(encoding='utf-8')
src = (HERE / 'isemon.py').read_text(encoding='utf-8')
print('\nThe page')
ok('the box shows it, as the other passwords do, and says so',
   "cfg.password_set ? 'set — leave as it is to keep it' : 'not set'" in page
   and "input.title = 'Shown back by its last two letters only." in page)
ok('...its dots are never sent back as a password, nor tried on the router',
   "String(one.api.password || '').indexOf('\\u2022') === 0 ? ''" in page
   and "if password.startswith('\\u2022'):" in src)
ok('the one-time boxes - signing in, a new password, a database administrator - stay hidden',
   page.count("type = 'password'") >= 5)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
