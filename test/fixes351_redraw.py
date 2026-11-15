#!/usr/bin/env python3
"""1.10.351: the sign-in cards (Windows, a certificate, the sign-in page) are
asked again right after their settings are saved, and the certificate's card
follows the port until root has put it in - nothing waits for F5."""
import re, sys
from pathlib import Path
SRC = Path(__file__).resolve().parent.parent
page = (SRC / 'web/index.php').read_text()
ok = fail = 0
def check(name, cond):
    global ok, fail
    if cond: ok += 1
    else: fail += 1; print('FAIL', name)
save = page[page.index("api('settings', {settings: want}).then"):]
save = save[:save.index('}).catch(function (e) {')]
check('the save asks the sign-in cards again', 'ssoReload()' in save)
check('for the keys of krb, cl, signin and the directory',
      "['krb', 'cl', 'signin', 'dir', 'dir2']" in save)
m = re.search(r'function ssoReload\(\) \{(.*?)\n\}', page, re.S)
check('ssoReload loads both', m and 'loadKerberos()' in m.group(1) and 'loadCertLogin()' in m.group(1))
m = re.search(r'function drawCertLogin\(d, anchor\) \{(.*?)\n\}', page, re.S)
check('the certificate card follows the port', m and 'ssoFollow(d)' in m.group(1))
m = re.search(r'function ssoFollow\(d\) \{(.*?)\n\}', page, re.S)
check('followed only while the pane is open, and not for ever',
      m and "paneLive('dir')" in m.group(1) and '120000' in m.group(1) and 'clearTimeout' in m.group(1))
m = re.search(r'function loadOsUsers\(\) \{(.*?)\n\}', page, re.S)
check('no refresh asked of a helper not there (users)', m and 'd.helper !== false' in m.group(1))
m = re.search(r'function loadSshKeys\(\) \{(.*?)\n\}', page, re.S)
check('no refresh asked of a helper not there (keys)', m and 'd.helper !== false' in m.group(1))
print('%d ok, %d failed' % (ok, fail))
sys.exit(1 if fail else 0)
