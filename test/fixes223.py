#!/usr/bin/env python3
"""1.10.223: the read-only view of the firewall shows isemon's own chain
ISEMON-IN as the kernel holds it, and the jump to it in INPUT.

    ./test/fixes223.py
"""
import os
import shutil
import subprocess
import sys
import tempfile
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
ok('the chain is drawn from what root read off the kernel',
   'mine = chain[FW.fam] || [];' in page and 'look.chain' in page)
ok('...in the same window as INPUT, below it, in blue',
   "mine.forEach(function (l) { put(l, true); });" in page and '.fw-pre .fw-ours{color:var(--info)}' in page)
ok('...the jump to it in INPUT blue as well', "put(l, l.indexOf('-j ISEMON-IN') >= 0)" in page)
ok('the note no longer says ISEMON-IN is left out', 'without ISEMON-IN' in page, False)

ok('the certificate card does not show what root did last',
   "card.appendChild(wrRootLine(d.root_state, 'TLS', true))" in page and
   'What root did last' not in page)

print('\nRoot')
work = Path(tempfile.mkdtemp(prefix='isemon-223-'))
try:
    (work / 'web').mkdir()
    script = work / 's.sh'
    script.write_text('iptables -N ISEMON-IN; iptables -I INPUT 1 -j ISEMON-IN; '
                      'iptables -A ISEMON-IN -p tcp --dport 22 -j ACCEPT; '
                      'iptables -A INPUT -p tcp --dport 10050 -j ACCEPT\n'
                      'python3 -I -c "import sys,json; sys.path.insert(0, \'%s\'); import isemon_web as w;'
                      'print(json.dumps([w.fw_now(4), w.fw_chain_now(4)]))"\n' % (ROOT / 'deploy'))
    ns = shutil.which('unshare') and subprocess.run(['unshare', '--net', 'true']).returncode == 0
    if ns and shutil.which('iptables'):
        got = subprocess.run(['unshare', '--net', 'bash', str(script)], capture_output=True, text=True,
                             env=dict(os.environ, ISEMON_STATE=str(work)))
        import json
        now, chain = json.loads(got.stdout.strip().splitlines()[-1])
        ok('INPUT is read with the jump to ISEMON-IN in it, where it stands',
           now[:2], [':INPUT ACCEPT [0:0]', '-A INPUT -j ISEMON-IN'])
        ok('...and the site\'s own lines after it', '-A INPUT -p tcp -m tcp --dport 10050 -j ACCEPT' in now)
        ok('ISEMON-IN as the kernel holds it', chain,
           ['-N ISEMON-IN', '-A ISEMON-IN -p tcp -m tcp --dport 22 -j ACCEPT'])
    else:
        print('  (no network namespace or iptables here: root\'s side not tried)')
finally:
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
