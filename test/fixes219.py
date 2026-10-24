#!/usr/bin/env python3
"""1.10.219: the whole php2shell procedure written down in docs/php2shell.md,
linked from INSTALL.md, and the guard for PHP as a whole in /etc/php.d named
where .user.ini alone was said to be enough."""
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
PASS = FAIL = 0


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    ' + what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


doc_path = HERE / 'docs' / 'php2shell.md'
ok('docs/php2shell.md is in the package', doc_path.is_file())
doc = doc_path.read_text(encoding='utf-8') if doc_path.is_file() else ''
install = (HERE / 'INSTALL.md').read_text(encoding='utf-8')
readme = (HERE / 'README.md').read_text(encoding='utf-8')
installer = (HERE / 'install.sh').read_text(encoding='utf-8')
vhost = (HERE / 'deploy' / 'nginx-isemon.conf').read_text(encoding='utf-8')

print('\nThe document')
ok('it is in English (no Czech letters)', bool(re.search('[ěščřžýáíéůúťďň]', doc, re.I)), False)
for what in ('CVE-2026-109618', 'CVE-2026-109619', '8.2.35', '8.3.36', '8.4.27', '8.5.12'):
    ok('names ' + what, what in doc)
for cmd in ("rpm -qa 'php*'", 'dnf module list --enabled php',
            "session.upload_progress.enabled = 0\\nsession.use_strict_mode = 1",
            '/etc/php.d/99-php2shell.ini', 'systemctl restart php-fpm',
            'dnf module enable -y php:8.2', "dnf distro-sync -y 'php*'", '.rpmnew',
            "dnf upgrade --refresh 'php*'", 'dnf updateinfo list --cve CVE-2026-109618',
            'rpm -q --changelog php-fpm', r'\(deleted\)$', 'isemon.conf.before-php2shell',
            './install.sh --upgrade', '-F a=b'):
    ok('has: ' + cmd, cmd in doc)
rule = re.search(r'if \(\$http_content_type ~\* "multipart"\) \{ return 403; \}', vhost)
ok('the nginx rule it shows is the one the vhost has', bool(rule) and rule.group(0) in doc)
ok('the paths it uses are the package\'s own',
   all(p in doc for p in ('/var/www/isemon', '/var/log/nginx/isemon-access.log',
                          '/etc/nginx/conf.d/isemon.conf'))
   and '/var/log/nginx/isemon-access.log' in vhost and 'WEB_DIR="/var/www/isemon"' in installer)
ok('it says .user.ini alone is not enough', 'not** a sufficient guard' in doc)
fences = doc.count('```')
ok('its code blocks are all closed', fences % 2, 0)
for block in re.findall(r'```bash\n(.*?)```', doc, re.S):
    r = subprocess.run(['bash', '-n'], input=block, text=True, capture_output=True)
    ok('a bash block parses: ' + block.strip().splitlines()[0][:50], r.returncode, 0)

print('\nWhere it is linked from')
ok('INSTALL.md links it', '(docs/php2shell.md)' in install)
ok('INSTALL.md sets the guard in /etc/php.d', '/etc/php.d/99-php2shell.ini' in install)
ok('the installer points to it', 'docs/php2shell.md' in installer)
ok('README names it under 1.10.219', 'docs/php2shell.md' in readme.split('1.10.218')[0])
r = subprocess.run(['bash', '-n', str(HERE / 'install.sh')], capture_output=True)
ok('install.sh still parses', r.returncode, 0)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
