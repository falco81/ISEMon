#!/usr/bin/env python3
"""1.10.276: a password or a token as plexmon's masked box shows it - one that
is kept by its last two letters, to a full administrator only; what is typed
dots, every letter. The settings, a backup destination's passwords and a
MikroTik's API password alike.

    ./test/fixes276_mask.py
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
import isemon                                        # noqa: E402

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
src = (ROOT / 'isemon.py').read_text()

print('The daemon: the last two letters to a full administrator only')
ok('a secret shown back: dots and its last two letters', isemon.secret_shown('Brand-New-98'),
   '•' * 10 + '98')
ok('a setting\'s: only to whoever may change it',
   "one['value'] = secret_shown(value) if may_change else ''" in src)
rows = [{'name': 'gw', 'api': {'user': 'isemon-read', 'password': isemon.seal_secret('Api-Pass-42')}}]
ok('a MikroTik\'s API password: its last two letters to a full administrator',
   isemon.rosapi_masked(rows, True)[0]['api']['password'], '•' * 9 + '42')
ok('...and nothing to anybody else - only that one is set',
   (isemon.rosapi_masked(rows, False)[0]['api']['password'],
    isemon.rosapi_masked(rows, False)[0]['api']['password_set']), ('', True))
ok('...as the settings give them', src.count('rosapi_masked(one.get(\'value\'), may_change)'), 1)

print('\nThe page: the masked box')
box = page[page.index('function maskShown(real) {'):page.index('function busy(button, on) {')]
ok('what is typed is dots; one that is kept is shown as it came', (
    "if (!real || real.charAt(0) === '\\u2022') return real;" in box,
    "return new Array(real.length + 1).join('\\u2022');" in box), (True, True))
ok('its value is what was typed, kept beside what is shown',
   "get: function () { return real; }," in box)
ok('typing into a kept one starts it afresh; nothing can be copied out', (
    "if (real.charAt(0) === '\\u2022') { real = ''; a = z = 0; }" in box,
    "i.addEventListener('copy', function (e) { e.preventDefault(); });" in box), (True, True))
ok('no password manager is offered it', ("data-lpignore" in box, "data-1p-ignore" in box),
   (True, True))
ok('loaded before anything that draws a box with it', page.index('function maskInput(') <
   page.index("  item.dataset.key = s.key;"))
ok('every secret setting', "      maskInput(input, input.value);\n" in page)
ok('a backup destination\'s password, its key\'s and its certificate\'s',
   'return maskInput(t, value || \'\');' in page)
ok('a MikroTik\'s API password', "if (key === 'password') maskInput(input, input.value);" in page)
ok('no secret setting is a plain password box any more (the last two letters hidden)',
   "      input.type = 'password';\n      input.setAttribute('data-lpignore'" not in page)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
