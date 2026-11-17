#!/usr/bin/env python3
"""1.10.362: what SELinux refuses, sorted by what puts it right (the selinux kit).

Root's helper with a pretend machine (getenforce, ausearch, audit2why,
matchpathcon, semodule, semanage, setsebool, restorecon on PATH): every
refusal read with its event, grouped, sorted into a boolean, a label, a port,
a rule of isemon's own local module, not for a button, not isemon's; put
right by ids only - root works the fix out itself; the local module written,
loaded, and a rule taken away again; a refusal from before what was put right
no longer counted; the report with the whole machine. Then the daemon, the
command line and the page.

    ./test/fixes362_selinux_kit.py
"""
import importlib
import io
import json
import os
import shutil
import sys
import tarfile
import tempfile
import time
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


work = Path(tempfile.mkdtemp(prefix='isemon-362-'))
M = work / 'machine'
BIN = work / 'bin'
STATE = work / 'state'
OURS = work / 'www' / 'isemon'
for d in (M, BIN, STATE / 'web', work / 'rootstate', work / 'rsyslog.d', OURS / 'assets'):
    d.mkdir(parents=True, exist_ok=True)
(OURS / 'assets' / 'core.js').write_text('x')

FAKES = {
    'getenforce': 'cat "$M/mode"',
    'getsebool': 'v=off; [ -f "$M/bool_$1" ] && v=$(cat "$M/bool_$1"); echo "$1 --> $v"',
    'setsebool': 'echo "setsebool $*" >> "$M/log"; echo on > "$M/bool_$2"',
    'semodule': 'case "$1" in -l|-lfull) cat "$M/modules" 2>/dev/null; exit 0;; esac\n'
                'echo "semodule $*" >> "$M/log"\n'
                'if [ "$1" = -r ]; then grep -v "^$2 " "$M/modules" > "$M/m2"; mv "$M/m2" "$M/modules"; exit 0; fi\n'
                '[ -f "$M/semodule_fail" ] && { echo "semodule: no" >&2; exit 1; }\n'
                'n=$(basename "$2" .cil); grep -q "^$n " "$M/modules" || echo "$n 1.0" >> "$M/modules"\n'
                'cp "$2" "$M/loaded-$n.cil"',
    'semanage': 'if [ "$2" = -l ]; then cat "$M/ports"; exit 0; fi\n'
                'if [ "$1" = export ]; then exit 0; fi\n'
                'echo "semanage $*" >> "$M/log"\n'
                'echo "$4 $6 $7" >> "$M/ports"',
    'restorecon': 'echo "restorecon $*" >> "$M/log"',
    'matchpathcon': 'echo "system_u:object_r:httpd_sys_content_t:s0"',
    'ausearch': 'cat "$M/avc" 2>/dev/null',
    'audit2why': 'while IFS= read -r l; do echo "$l"; case "$l" in *ALLOWED*) '
                 'echo "	Was caused by:"; echo "		Unknown - would be allowed by active policy";; '
                 '*CONNECTS*) echo "	Was caused by:"; echo "	One of the following booleans was set '
                 'incorrectly."; echo "	Allow access by executing:"; '
                 'echo "	# setsebool -P httpd_can_network_connect 1";; '
                 '*EXECS*) echo "	Allow access by executing:"; echo "	# setsebool -P httpd_execmem 1";; '
                 'esac; done',
}
for name, body in FAKES.items():
    p = BIN / name
    p.write_text('#!/bin/sh\nM=%s\n%s\n' % (M, body))
    p.chmod(0o755)

os.environ.update({
    'PATH': '%s:%s' % (BIN, os.environ.get('PATH', '/usr/bin:/bin')),
    'ISEMON_STATE': str(STATE), 'ISEMON_WEB_NO_SERVICES': '1',
    'ISEMON_ROOT_STATE': str(work / 'rootstate'),
    'ISEMON_SELINUX_CONFIG': str(M / 'config'), 'ISEMON_SELINUX_RELABEL': str(M / 'autorelabel'),
    'ISEMON_SELINUX_CMDLINE': str(M / 'cmdline'), 'ISEMON_SELINUX_CIL': str(M / 'isemon_server.cil'),
    'ISEMON_SELINUX_LOCAL_CIL': str(M / 'isemon_local.cil'),
    'ISEMON_SELINUX_AUDITD': 'active', 'ISEMON_SELINUX_LABELS': str(M / 'labels.json'),
    'ISEMON_RSYSLOG': str(work / 'rsyslog.d'),
})
sys.path.insert(0, str(ROOT / 'deploy'))
web = importlib.import_module('isemon_web')
shutil.copy(str(ROOT / 'deploy' / 'isemon_server.cil'), str(M / 'isemon_server.cil'))
web.SE_OUR_PATHS = web.SE_OUR_PATHS + (str(OURS),)
web.ssh_ports = lambda: ['2222']
web.rsyslog_ports = lambda: []

T = int(time.time()) - 3000
N = [600]


def avc(ago, perms, comm, st, tt, cls, more='', exe='', path=''):
    N[0] += 1
    mid = '%d.%03d:%d' % (T + ago, 100, N[0])
    out = ('type=AVC msg=audit(%s): avc:  denied  { %s } for  pid=1 comm="%s" %s '
           'scontext=system_u:system_r:%s:s0 tcontext=system_u:object_r:%s:s0 tclass=%s '
           'permissive=1\n' % (mid, perms, comm, more, st, tt, cls))
    if exe:
        out += 'type=SYSCALL msg=audit(%s): arch=c000003e syscall=59 success=yes exe="%s"\n' % (mid, exe)
    if path:
        out += 'type=PATH msg=audit(%s): item=0 name="%s" inode=1\n' % (mid, path)
    return out


AVC = (avc(10, 'read', 'nginx', 'httpd_t', 'default_t', 'file', 'name="core.js"',
           path=str(OURS / 'assets' / 'core.js'))
       + avc(20, 'name_bind', 'sshd', 'sshd_t', 'unreserved_port_t', 'tcp_socket', 'src=2222')
       + avc(30, 'nnp_transition', 'isemon-bg', 'unconfined_service_t', 'chronyc_t', 'process2')
       + avc(31, 'nnp_transition', 'isemon-bg', 'unconfined_service_t', 'chronyc_t', 'process2')
       + avc(40, 'write', 'chronyc', 'chronyc_t', 'unconfined_service_t', 'fifo_file', 'path="pipe:[123]"')
       + avc(50, 'name_connect', 'CONNECTS', 'httpd_t', 'unreserved_port_t', 'tcp_socket', 'dest=9851')
       + avc(60, 'execute', 'isemon-x', 'unconfined_service_t', 'shell_exec_t', 'file', 'name="sh"',
             path='/usr/bin/sh')
       + avc(70, 'read', 'isemon-y', 'unconfined_service_t', 'shadow_t', 'file', 'name="shadow"',
             path='/etc/shadow')
       + avc(75, 'execmem', 'EXECS', 'httpd_t', 'httpd_t', 'process', 'name="x"',
             path=str(OURS / 'x'))
       + avc(80, 'name_connect', 'php-fpm', 'httpd_t', 'unreserved_port_t', 'tcp_socket', 'dest=9862')
       + avc(90, 'write', 'smbd', 'smbd_t', 'home_root_t', 'dir', 'name="share"')
       + avc(95, 'read', 'ALLOWED', 'httpd_t', 'var_run_t', 'file', 'name="api-token"',
             path='/run/isemon/api-token'))


def machine(avc_text=AVC, mode='Permissive'):
    for f in M.iterdir():
        if f.name.startswith(('bool_', 'loaded-')) or f.name in ('log', 'semodule_fail'):
            f.unlink()
    (M / 'mode').write_text(mode + '\n')
    (M / 'config').write_text('SELINUX=%s\nSELINUXTYPE=targeted\n' % mode.lower())
    (M / 'cmdline').write_text('ro\n')
    (M / 'modules').write_text('isemon_server 1.0\n')
    (M / 'ports').write_text('http_port_t tcp 80, 443\nssh_port_t tcp 22\n')
    (M / 'avc').write_text(avc_text)
    (M / 'labels.json').write_text(json.dumps({'/run/isemon': 'httpd_var_run_t',
                                               '/run/isemon/api-token': 'httpd_var_run_t',
                                               '/var/www/isemon': 'httpd_sys_content_t'}))
    (M / 'bool_httpd_can_network_connect').write_text('on')


def log():
    try:
        return (M / 'log').read_text().splitlines()
    except OSError:
        return []


WANT = {'booleans': [{'name': 'httpd_can_network_connect', 'why': 'the pages ask the daemon'}],
        'ports': [], 'facts': {'api_port': 9851}}

print('What SELinux refuses, sorted')
machine()
look = web.se_look(WANT)
by = {}
for f in look['findings']:
    by.setdefault(f['kind'], []).append(f)
kinds = {k: sorted('%s>%s' % (f['st'], f['tt']) for f in v) for k, v in by.items()}
ok('a file not labelled as the policy says: a label', kinds.get('label'), ['httpd_t>default_t'])
ok('...put right by restorecon of that file, said exactly',
   by['label'][0]['fix'], 'restorecon -v %s' % (OURS / 'assets' / 'core.js'))
ok('sshd on a port with no type: a port, ssh_port_t', (kinds.get('port'), by['port'][0]['fix']),
   (['sshd_t>unreserved_port_t'], 'semanage port -a -t ssh_port_t -p tcp 2222'))
ok('the pages asking the daemon: the boolean audit2why names',
   (kinds.get('boolean'), by['boolean'][0]['fix']),
   (['httpd_t>unreserved_port_t'], 'setsebool -P httpd_can_network_connect on'))
ok('isemon starting chronyc, and chronyc answering it: rules of isemon\'s own',
   kinds.get('rule'), ['chronyc_t>unconfined_service_t', 'unconfined_service_t>chronyc_t'])
rule = [f for f in by['rule'] if f['tt'] == 'chronyc_t'][0]
ok('...the same refusal twice: one finding, counted twice', rule['count'], 2)
ok('...exactly the rule', rule['fix'], '(allow unconfined_service_t chronyc_t (process2 (nnp_transition)))')
nofix = {f['tt']: f['why'] for f in by.get('nofix', [])}
ok('running a shell, reading shadow, a boolean that allows far more: not for a button',
   sorted(nofix), ['httpd_t', 'shadow_t', 'shell_exec_t'])
ok('...each says why', ('security-sensitive' in nofix['shadow_t'],
                        'execute' in nofix['shell_exec_t'],
                        'httpd_execmem' in nofix['httpd_t']), (True, True, True))
ok('another port of the web server, samba: not isemon\'s', kinds.get('notours'),
   ['httpd_t>unreserved_port_t', 'smbd_t>home_root_t'])
ok('allowed by the policy loaded now: not shown, counted as settled',
   (any(f['comm'] == 'ALLOWED' for f in look['findings']), look['settled']), (False, 1))
ok('the counts', (look['fixable'], look['nofix'], look['notours']), (5, 3, 2))
again = web.se_look(WANT)
ok('the same refusal has the same id at every look',
   sorted(f['id'] for f in again['findings']) == sorted(f['id'] for f in look['findings']))
ok('ids are 12 hex', all(web.SE_ID_RE.match(f['id']) for f in look['findings']))

print('\nPut right by ids only')
ids = [f['id'] for f in look['findings'] if f['kind'] in ('label', 'port', 'rule')]
said = []
done = web.se_fix(dict(WANT, ids=ids + ['000000000000'], by='boss'), said)
ok('everything asked and still there put right', sorted(done), sorted(ids))
ok('...an id that is not there: said, nothing done for it',
   any('000000000000: not there' in s for s in said))
L = log()
ok('restorecon of the file, semanage port -a, the local module put in',
   (any(x == 'restorecon -v %s' % (OURS / 'assets' / 'core.js') for x in L),
    'semanage port -a -t ssh_port_t -p tcp 2222' in L,
    any(x.startswith('semodule -i') and 'isemon_local.cil' in x for x in L)), (True, True, True))
cil = (M / 'loaded-isemon_local.cil').read_text()
ok('the local module: each rule in a block of its own, exactly what was refused',
   ('(optional isemon_local_%s\n    (allow unconfined_service_t chronyc_t (process2 (nnp_transition))))'
    % rule['id']) in cil and cil.count('(optional ') == 2)
ok('...its parentheses balanced', sum(1 if c == '(' else -1 if c == ')' else 0
                                      for line in cil.splitlines() if not line.startswith(';')
                                      for c in line), 0)
ok('...kept beside it as put in', (M / 'isemon_local.cil.in-policy').exists())
after = web.se_look(WANT)
kinds2 = {}
for f in after['findings']:
    kinds2.setdefault(f['kind'], []).append(f['id'])
ok('looked at again: what was put right is "put right", nothing fixable left of it',
   (sorted(kinds2.get('done', [])), 'label' in kinds2, 'port' in kinds2, 'rule' in kinds2),
   (sorted(ids), False, False, False))
ok('...the local rules listed', sorted(x['id'] for x in after['local']['rules']),
   sorted(f['id'] for f in by['rule']))
ok('...and the refusals of before no longer counted for enforcing',
   web.se_denials()['total'] < len([1 for x in AVC.splitlines() if 'avc:' in x]) - 3)
new = AVC + avc(3000, 'nnp_transition', 'isemon-bg', 'unconfined_service_t', 'chronyc_t',
                'process2').replace(str(T + 3000), str(int(time.time()) + 5))
(M / 'avc').write_text(new)
back = {f['id']: f['kind'] for f in web.se_look(WANT)['findings']}
ok('a refusal of it from after: it comes back', back.get(rule['id']), 'rule')
(M / 'avc').write_text(AVC)

print('\nThe page asks nothing but ids')
for bad in ({'ids': ['../../etc']}, {'ids': []}, {'ids': 'x'}):
    try:
        web.se_fix(dict(WANT, **bad), [])
        ok('a request without ids that are ids: refused (%r)' % bad, False)
    except web.Refused:
        ok('a request without ids that are ids: refused (%r)' % bad, True)
nf = [f['id'] for f in by['nofix']] + [f['id'] for f in by['notours']]
said = []
ok('not for a button, not isemon\'s: never put right, even asked',
   (web.se_fix(dict(WANT, ids=nf), said), all('not put right from here' in s for s in said)),
   ([], True))

print('\nA rule taken away')
said = []
web.se_rule_drop({'rule': rule['id']}, said)
left = web.se_local_list()
ok('one taken away: the module written again without it',
   ([x['id'] for x in left], rule['id'] in (M / 'loaded-isemon_local.cil').read_text()),
   ([f['id'] for f in by['rule'] if f['id'] != rule['id']], False))
web.se_rule_drop({'rule': left[0]['id']}, said)
ok('the last taken away: the module out of the policy',
   ('semodule -r isemon_local' in log(), web.se_local_list(), (M / 'isemon_local.cil').exists()),
   (True, [], False))
try:
    web.se_rule_drop({'rule': 'abcdefabcdef'}, [])
    ok('a rule that is not there: refused', False)
except web.Refused:
    ok('a rule that is not there: refused', True)

print('\nThrough the request, as the daemon asks')
machine()
for f in (work / 'rootstate').iterdir():
    f.unlink()


def ask(r):
    (STATE / 'web' / 'selinux.ask').write_text(json.dumps(dict(r, at=time.time())))
    web.selinux_part()
    return json.loads((STATE / 'web' / 'selinux.json').read_text())


got = ask(dict(WANT, do='look', id='l1'))
ok('look: the check and the findings', (got['ok'], got['data']['mode'], bool(got['data']['look'])),
   (True, 'Permissive', True))
fid = [f['id'] for f in got['data']['look']['findings'] if f['kind'] == 'port'][0]
got = ask(dict(WANT, do='fix', ids=[fid], by='boss', id='f1'))
ok('fix: done, said, and looked at again at once',
   (got['ok'], any('ssh_port_t' in s for s in got['data']['said']),
    [f['kind'] for f in got['data']['look']['findings'] if f['id'] == fid]), (True, True, ['done']))
(STATE / 'web' / 'selinux.ask').write_text(json.dumps(dict(WANT, do='fix', ids=[fid],
                                                           at=time.time() - 3600)))
web.selinux_part()
ok('a fix asked long ago: not done', json.loads((STATE / 'web' / 'selinux.json').read_text())['ok'],
   False)
got = ask(dict(WANT, do='check', id='c1'))
ok('a check as before: no findings in it', (got['ok'], 'look' in got['data']), (True, False))

print('\nThe report: the whole machine as well')
got = ask(dict(WANT, do='report', id='r1'))
data = (STATE / 'web' / 'selinux-report.tar.gz').read_bytes()
names = sorted(m.name.split('/', 1)[1] for m in tarfile.open(fileobj=io.BytesIO(data)).getmembers())
ok('findings.json and os/* beside the parts it had',
   all(n in names for n in ('findings.json', 'os/processes.txt', 'os/booleans.txt', 'os/ports.txt',
                            'os/modules.txt', 'os/local-changes.txt', 'os/semanage-export.txt',
                            'os/listening.txt', 'check.json', 'avc-raw.txt', 'README.txt')))

print('\nThe module, the installer')
cilsrc = (ROOT / 'deploy' / 'isemon_server.cil').read_text()
ok('ssh and ssh-keygen let start under NoNewPrivileges, each in a block of its own',
   ('(optional isemon_server_nnp_ssh\n' in cilsrc, '(optional isemon_server_nnp_ssh_keygen\n' in cilsrc),
   (True, True))
inst = (ROOT / 'install.sh').read_text()
ok('--uninstall takes the local module out too', 'semodule -r isemon_local' in inst)
ok('...the installer still never touches the mode', ('setenforce' in inst, 'SELINUX=' in inst),
   (False, False))

print('\nThe daemon, the command line, the page')
sys.path.insert(0, str(ROOT))
import isemon                                        # noqa: E402
ok('the actions', all(a in isemon.SE_ACTIONS for a in ('look', 'fix', 'rule_drop')))
try:
    isemon.selinux_ask(None, 'fix', 'boss', ids=['nope'])
    ok('fix without ids: refused', False)
except ValueError:
    ok('fix without ids: refused', True)
try:
    isemon.selinux_ask(None, 'rule_drop', 'boss', rule='x')
    ok('rule_drop without a rule id: refused', False)
except ValueError:
    ok('rule_drop without a rule id: refused', True)


class Store(object):
    def __init__(self, data):
        self.data = data

    def get_meta(self, k):
        return json.dumps({'data': self.data})


ok('an alert while something can be put right',
   [a['title'] for a in isemon.selinux_alerts(Store({'mode': 'Permissive', 'look': {'fixable': 3}}))],
   ['SELinux refuses isemon something - 3 can be put right'])
ok('...none when nothing can, or SELinux is off',
   (isemon.selinux_alerts(Store({'mode': 'Permissive', 'look': {'fixable': 0}})),
    isemon.selinux_alerts(Store({'mode': 'Disabled', 'look': {'fixable': 2}}))), ([], []))
src = (ROOT / 'isemon.py').read_text()
ok('the command line: look, fix by ids or all, the rules',
   all(x in src for x in ("'--selinux-fix'", "'--selinux-all'", "'--selinux-rules'", "'--take-away'",
                          "choices=('check', 'look', 'prepare', 'enforce', 'permissive')")))
page = (ROOT / 'web' / 'index.php').read_text()
ok('the page: the findings sorted, ticked, and only their ids sent',
   ('function seLook(n, s)' in page and "seAsk('fix', {ids: ids})" in page
    and "seAsk('rule_drop', {rule: x.id})" in page))
ok('...a confirm saying exactly what root will do', 'Root does exactly this - nothing else' in page)
ok('...Look again looks at every refusal', "api('selinux', {action: 'look'})" in page)
ok('...the steps as they were', "enf.disabled = !!n.pending || !s.ready;" in page)

print('\n%d ok, %d failed' % (PASS, FAIL))
shutil.rmtree(str(work), ignore_errors=True)
sys.exit(1 if FAIL else 0)
