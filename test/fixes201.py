#!/usr/bin/env python3
"""1.10.201: the installer receives the logs on every install and upgrade
(rsyslog and its modules, the permissions, rsyslog's umask, an ACL on what
is there, the receiver, the rotation) without replacing anything of the
machine's own; it gives a PostgreSQL account the right to tune; the
accounts table lines up.

The installer's own functions are run here, cut out of install.sh, against
a folder of their own and with the system's programs stood in for.

    ./test/fixes201.py
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

PASS = FAIL = 0


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


installer = (HERE.parent / 'install.sh').read_text(encoding='utf-8')
page = (HERE.parent / 'web' / 'index.php').read_text(encoding='utf-8')

print('\nThe installer as it reads')
ok('it parses', subprocess.run(['bash', '-n', str(HERE.parent / 'install.sh')]).returncode, 0)
ok('receiving is the default of a fresh install, and --no-syslog turns it off',
   'WITH_SYSLOG="yes"\n' in installer and '--no-syslog)       WITH_SYSLOG=""' in installer)
upgrade = installer[installer.index('if [[ -n "$DO_UPGRADE" ]]; then\n    step "Upgrading'):
                    installer.index('# A fresh install\n')]
ok('...a plain upgrade never touches it, only --upgrade --with-syslog (1.10.202)',
   'if [[ -n "$SYSLOG_ASKED" && -n "$WITH_SYSLOG" ]]; then\n        setup_receiving upgrade'
   in upgrade and upgrade.count('setup_receiving') == 1
   and 'SYSLOG_ASKED="yes"' in installer)
ok('...nor the tuning rights, only --upgrade --db-rights',
   'if [[ -n "$DO_DB_RIGHTS" ]]; then\n        db_tune_rights' in upgrade
   and upgrade.count('db_tune_rights') == 1)
ok('...nor installs polkit',
   '( -z "$DO_UPGRADE" || -n "$DO_DB_RIGHTS" )' in installer)
ok('the tuning rights on a fresh install, and on their own with --db-rights',
   installer.count('\ndb_tune_rights\n') == 1 and '--db-rights)       DO_DB_RIGHTS="yes"' in installer
   and 'if [[ -n "$DO_DB_RIGHTS" && -z "$DO_UPGRADE" ]]; then' in installer)
ok('the packages of the RELP and TLS receiver',
   'rsyslog rsyslog-relp rsyslog-openssl' in installer)

FUNCS = ('say', 'note', 'good', 'warn', 'step', 'fail', 'run', 'install_substituted',
         'write_file', 'rsyslog_listening_files', 'remote_rotated_elsewhere',
         'receiving_packages', 'receiving_umask', 'receiving_folder', 'setup_receiving')


def cut(name):
    m = re.search(r'(?ms)^%s\(\) \{.*?^\}\n' % re.escape(name), installer)
    if not m:
        m = re.search(r'(?m)^%s\(\)[ ]+\{.*\}\n' % re.escape(name), installer)
    assert m, name
    return m.group(0)


body = '\n'.join(cut(f) for f in FUNCS)
GROUP = 'daemon'
MOCKS = {
    'systemctl': r'''#!/bin/bash
echo "systemctl $*" >> "$T/log"
case "$1" in
  show) echo "${UMASK_VAL:-0066}";;
  is-active) [[ "$*" == *syslog-ng* && -n "$SYSLOG_NG" ]] && exit 0; exit 3;;
esac
exit 0''',
    'rpm': '#!/bin/bash\n[[ -n "$NO_PKGS" ]] && exit 1; exit 0',
    'dnf': '#!/bin/bash\necho "dnf $*" >> "$T/log"; exit 0',
    'rsyslogd': '#!/bin/bash\necho "rsyslogd $*" >> "$T/log"\n[[ -n "$RSYSLOG_BAD" ]] && { echo "error: bad"; exit 1; }; exit 0',
    'ss': '#!/bin/bash\nexit 0',
    'logrotate': '#!/bin/bash\nexit 0',
    'setfacl': '#!/bin/bash\necho "setfacl $*" >> "$T/log"; exit 0',
    'restorecon': '#!/bin/bash\nexit 0',
    'firewall-cmd': '#!/bin/bash\necho "firewall-cmd $*" >> "$T/log"; exit 0',
}


def scene(how='fresh', setup=None, **env):
    t = Path(tempfile.mkdtemp(prefix='isemon-201-'))
    b = t / 'bin'
    b.mkdir()
    for name, text in MOCKS.items():
        (b / name).write_text(text + '\n')
        (b / name).chmod(0o755)
    for d in ('etc/rsyslog.d', 'etc/logrotate.d', 'etc/cron.daily', 'var/log'):
        (t / d).mkdir(parents=True)
    (t / 'etc/rsyslog.conf').write_text('module(load="imjournal")\n')
    (t / 'etc/logrotate.conf').write_text('weekly\ninclude /etc/logrotate.d\n')
    (t / 'log').write_text('')
    if setup:
        setup(t)
    script = '''set -euo pipefail
DRY_RUN=""; PKG="dnf"; VERSION="1.10.201"; SERVICE_USER="%(g)s"; LOG_FROM=""
SOURCE_DIR="%(src)s"
C_HEAD=""; C_OK=""; C_WARN=""; C_BAD=""; C_DIM=""; C_OFF=""
RSYSLOG_PERMS_FILE="$T/etc/rsyslog.d/00-isemon-permissions.conf"
RSYSLOG_FILE="$T/etc/rsyslog.d/10-ise.conf"
REMOTE_LOGROTATE_FILE="$T/etc/logrotate.d/remote-logs"
TIDY_CRON_FILE="$T/etc/cron.daily/isemon-logs-tidy"
REMOTE_DIR="$T/var/log/remote"
RSYSLOG_UMASK_DROPIN="$T/etc/systemd/system/rsyslog.service.d/isemon-umask.conf"
RSYSLOG_MAIN="$T/etc/rsyslog.conf"; RSYSLOG_DIR="$T/etc/rsyslog.d"
LOGROTATE_MAIN="$T/etc/logrotate.conf"; LOGROTATE_DIR="$T/etc/logrotate.d"
%(body)s
setup_receiving %(how)s
echo FINISHED
''' % {'g': GROUP, 'src': str(HERE.parent), 'body': body, 'how': how}
    e = dict(os.environ, T=str(t), PATH='%s:%s' % (b, os.environ['PATH']))
    e.update(env)
    r = subprocess.run(['bash', '-c', script], capture_output=True, text=True, env=e)
    out = r.stdout + r.stderr
    return t, out, (t / 'log').read_text()


print('\nA machine with nothing set up')
t, out, log = scene()
ok('it runs to the end', 'FINISHED' in out, True)
ok('the permissions for what rsyslog makes', (t / 'etc/rsyslog.d/00-isemon-permissions.conf')
   .read_text().count('$FileGroup      %s' % GROUP), 1)
ok('...the receiver, with the group of the account',
   'fileGroup="%s"' % GROUP in (t / 'etc/rsyslog.d/10-ise.conf').read_text())
ok('...rsyslog\'s umask of 0066 loosened to 0027',
   'UMask=0027' in (t / 'etc/systemd/system/rsyslog.service.d/isemon-umask.conf').read_text())
ok('...checked, then restarted', ('rsyslogd -N1' in log, 'systemctl restart rsyslog' in log),
   (True, True))
st = os.stat(t / 'var/log/remote')
ok('...the folder made 0750, the account\'s group',
   (oct(st.st_mode & 0o777), st.st_gid), ('0o750', __import__('grp').getgrnam(GROUP).gr_gid))
ok('...an ACL on what is in it', 'setfacl -R -m u:%s:rX' % GROUP in log)
ok('...the rotation, with the group on create',
   'create 0640 root %s' % GROUP in (t / 'etc/logrotate.d/remote-logs').read_text())
ok('...and the daily tidy', (t / 'etc/cron.daily/isemon-logs-tidy').exists())
ok('...and no firewall opened when there is none', 'firewall-cmd' in log, False)
shutil.rmtree(t)

print('\nA umask that lets the group read')
t, out, log = scene(UMASK_VAL='0022')
ok('is left as it is', (t / 'etc/systemd/system/rsyslog.service.d/isemon-umask.conf').exists(),
   False)
shutil.rmtree(t)

print('\nA machine that already receives its logs its own way')


def own(t):
    (t / 'etc/rsyslog.d/05-mine.conf').write_text('module(load="imudp")\ninput(type="imudp" port="514")\n')
    (t / 'etc/rsyslog.d/00-isemon-permissions.conf').write_text('# mine\n')
    (t / 'etc/logrotate.d/syslog-remote').write_text('/var/log/remote/*/*.log {\n daily\n create 0640 root %s\n}\n' % GROUP)
    (t / 'var/log/remote').mkdir()
    (t / 'var/log/remote/x.log').write_text('a\n')


t, out, log = scene('upgrade', own)
ok('no second receiver', (t / 'etc/rsyslog.d/10-ise.conf').exists(), False)
ok('...its own permissions file kept', (t / 'etc/rsyslog.d/00-isemon-permissions.conf')
   .read_text(), '# mine\n')
ok('...no second rotation', (t / 'etc/logrotate.d/remote-logs').exists(), False)
ok('...and said', ('already listens' in out, 'is rotated already' in out), (True, True))
ok('...its file untouched', (t / 'var/log/remote/x.log').read_text(), 'a\n')
ok('...and no tidy deleting what its own rotation keeps',
   (t / 'etc/cron.daily/isemon-logs-tidy').exists(), False)
shutil.rmtree(t)

print('\nA configuration rsyslog refuses')
t, out, log = scene(RSYSLOG_BAD='1')
ok('what was added is taken out again',
   ((t / 'etc/rsyslog.d/10-ise.conf').exists(),
    (t / 'etc/rsyslog.d/00-isemon-permissions.conf').exists()), (False, False))
ok('...and rsyslog is not restarted', 'systemctl restart rsyslog' in log, False)
shutil.rmtree(t)

print('\nsyslog-ng instead')
t, out, log = scene(SYSLOG_NG='1')
ok('rsyslog is not set up', ((t / 'etc/rsyslog.d/10-ise.conf').exists(), 'dnf' in log),
   (False, False))
ok('...and what to write in syslog-ng is said', 'group(%s) perm(0640)' % GROUP in out)
shutil.rmtree(t)

print('\nThe packages')
t, out, log = scene(NO_PKGS='1')
ok('rsyslog, its RELP and its TLS modules installed where missing',
   'dnf install -y rsyslog rsyslog-relp rsyslog-openssl' in log)
shutil.rmtree(t)

print('\nThe tuning rights')
m = re.search(r'(?ms)^db_tune_rights\(\) \{.*?^\}\n', installer)
fn = m.group(0) if m else ''
ok('PostgreSQL 15 and newer, as postgres over its own socket',
   'runuser -u postgres -- psql' in fn and '150000' in fn)
ok('...only the settings the dashboard tunes, reloading, and reading the settings',
   all(w in fn for w in ('GRANT ALTER SYSTEM ON PARAMETER', 'pg_reload_conf()',
                         'pg_read_all_settings', 'TUNE_PG_NAMES')))
ok('...only for a server on this machine', 'not this machine' in fn)
ok('...no password asked or kept', 'password' not in fn.lower().replace(
   "an administrator's password", ''))

print('\nThe accounts table')
ok('the row\'s buttons in one line, centred', '.rowacts{display:flex;align-items:center' in page)
ok('...a picker the height of the small buttons', 'select.small{font-size:12.5px' in page)
ok('...the cells centred on it', 'table.users td{vertical-align:middle}' in page)
ok('...and "last signed in" written as "made" is',
   "var last = u.last_in ? stampCell(u.last_in) : el('td', '', 'never');" in page)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
