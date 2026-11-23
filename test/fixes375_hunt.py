#!/usr/bin/env python3
"""1.10.375: bug hunt, round 4 of 10 - the settings as they are checked, the
installer, and the pages' forms and lists.

    ./test/fixes375_hunt.py
"""
import subprocess
import sys
import tempfile
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


def refused(key, value):
    try:
        isemon.check_setting(key, value)
        return False
    except ValueError:
        return True


print('The settings')
ok('the whitelist never spares half of IPv4 written as an IPv6 range',
   refused('never_block', '::ffff:128.0.0.0/97'), True)
ok('...a /8 still may be', refused('never_block', '10.0.0.0/8'), False)
ok('a TACACS place typed wrong is said, not dropped', refused('tacacs_from', '10.0.0.x=Jump'), True)
ok('...addresses, ranges and names as ever',
   refused('tacacs_from', '10.9.0.0-10.9.0.63=Jump, 192.168.251.10=LogHost, 2001:db8::/48'),
   False)
ok('the same for the token server\'s', refused('otp_from', 'vpn-head=VPN'), True)
ok('the certificate\'s port is never another service\'s', refused('certlogin_port', 3306), True)
ok('...one of its own may be', refused('certlogin_port', 8443), False)
ok('a ban source switched off by JSON false', isemon.check_setting('ban_from_tacacs', False), 'off')
ok('...and on by true', isemon.check_setting('ban_from_tacacs', True), 'on')

print('Importing a configuration')
folder = Path(tempfile.mkdtemp(prefix='isemon-375-'))
for k, v in dict(STATE_DIR=folder, DB_FILE=folder / 'c.db', BACKUP_DIR=folder / 'b',
                 DUMP_DIR=folder / 'd', RUN_DIR=folder, LOG_DIR=folder,
                 CONFIG_FILE=folder / 'config.json', _LOG_PATH=folder / 'c.log',
                 TOKEN_FILE=folder / 'tok').items():
    setattr(isemon, k, v)
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0})
d = isemon.Daemon(isemon.Storage(isemon.DB_FILE))
was = int(isemon.CONFIG.get('api_port') or 0)
said = d.import_config({'_what': 'isemon configuration', 'settings': {'api_port': was + 17}},
                       by='test')
ok('the daemon\'s own port is not carried from another machine',
   int(isemon.CONFIG.get('api_port') or 0), was)
ok('...and said so', any('port' in str(m) for m in (said or {}).get('missing', [])))

print('The installer')
sh = (ROOT / 'install.sh').read_text()
ok('install.sh reads', subprocess.run(['bash', '-n', str(ROOT / 'install.sh')]).returncode, 0)
ok('no time service kept by another, or chronyd switched off, does not stop it',
   'other="$(time_kept_by || true)"' in sh
   and 'state="$(systemctl is-enabled chronyd 2>/dev/null || true)"' in sh)
ok('postgres that cannot sign in does not stop it',
   "pg_as -c 'SHOW server_version_num' 2>/dev/null | tr -dc 0-9 || true)" in sh)
ok('a failed upgrade takes the server out of maintenance',
   '"$BIN_LINK" --maintenance off >/dev/null 2>&1 && MAINT_MINE=""' in sh)
ok('--uninstall --yes removes', '[[ -n "$ASSUME_YES" ]] || confirm "Go ahead?" n' in sh)
end = (ROOT / 'deploy' / 'rsyslog-permissions-end.conf').read_text()
ok('the system\'s own logs keep their own permissions after the receivers',
   '$FileGroup      root' in end and '$FileCreateMode 0600' in end
   and 'RSYSLOG_PERMS_END_FILE' in sh)

print('The pages')
page = (ROOT / 'web' / 'index.php').read_text()
ok('the find box closed is not opened again by its own focus',
   "FIND_FROM = document.activeElement === $('findbox') ? null" in page)
ok('"... ago" sorts newest first', "return /\\bago\\b/.test(t) ? -secs : secs;" in page)
ok('1048575 bytes are 1.0 MB, not 1024.0 kB', 'Number(n.toFixed(1)) >= 1024' in page)
ok('an unsaved console switch survives the pane drawn again', 'var CONSOLE_WANT = null;' in page)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
