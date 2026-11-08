#!/usr/bin/env python3
"""1.10.320: the daemon (NoNewPrivileges) starting chronyc - the move into
chronyc_t let through by isemon's module; and what was refused said by the
program it came from, the thread's hex-encoded name read.

    ./test/fixes320_selinux_nnp.py
"""
import importlib
import os
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


work = Path(tempfile.mkdtemp(prefix='isemon-320-'))
(work / 'bin').mkdir()
(work / 'avc').write_text(
    'type=SYSCALL msg=audit(1794154800.757:1882): arch=c000003e syscall=59 success=yes exit=0 '
    'comm=5468726561642D333531202870726F exe="/usr/bin/chronyc" subj=system_u:system_r:chronyc_t:s0\n'
    'type=AVC msg=audit(1794154800.757:1882): avc:  denied  { nnp_transition } for  pid=24013 '
    'comm=5468726561642D333531202870726F scontext=system_u:system_r:unconfined_service_t:s0 '
    'tcontext=system_u:system_r:chronyc_t:s0 tclass=process2 permissive=1\n')
for name, body in (('ausearch', 'cat "%s/avc"' % work), ('audit2why', 'cat >/dev/null')):
    p = work / 'bin' / name
    p.write_text('#!/bin/sh\n%s\n' % body)
    p.chmod(0o755)
os.environ['PATH'] = '%s:%s' % (work / 'bin', os.environ.get('PATH', '/usr/bin:/bin'))
os.environ['ISEMON_WEB_NO_SERVICES'] = '1'
sys.path.insert(0, str(ROOT / 'deploy'))
web = importlib.import_module('isemon_web')

print('What was refused, as it reads')
ok('a hex-encoded thread name read', web.se_audit_word('5468726561642D333531202870726F'),
   'Thread-351 (pro')
ok('a quoted one as it is; a plain word as it is',
   (web.se_audit_word('"php-fpm"'), web.se_audit_word('rsyslogd')), ('php-fpm', 'rsyslogd'))
d = web.se_denials()
ok('the refusal said with the program it came from (the event\'s SYSCALL line)',
   [(g['source'], g['target'], g['perms'], g['what']) for g in d['groups']],
   [('unconfined_service_t', 'chronyc_t', 'nnp_transition', 'Thread-351 (pro /usr/bin/chronyc')])

print('\nThe module')
cil = (ROOT / 'deploy' / 'isemon_server.cil').read_text()
ok('the daemon may start chronyc into chronyc_t (NoNewPrivileges), in a block of its own',
   '(optional isemon_server_nnp_chronyc\n    (allow unconfined_service_t chronyc_t '
   '(process2 (nnp_transition))))' in cil)
ok('...nothing else let through for the unconfined domain',
   cil.count('allow unconfined_service_t'), 1)
ok('...the parentheses balanced',
   sum(1 if c == '(' else -1 if c == ')' else 0 for line in cil.splitlines()
       if not line.lstrip().startswith(';') for c in line), 0)
ok('isemon.service still runs with NoNewPrivileges',
   'NoNewPrivileges=yes' in (ROOT / 'deploy' / 'isemon.service').read_text())

print('\n%d passed, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
