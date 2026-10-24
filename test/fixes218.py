#!/usr/bin/env python3
"""1.10.218: php2shell (CVE-2026-109618, CVE-2026-109619) - the dashboard
never needs PHP to take a request body apart, the web server refuses
multipart bodies, the installer puts that rule into a vhost of the site's
own, and an administrator is told when the PHP running the page is not
fixed."""
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))

PASS = FAIL = 0


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    ' + what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


page = (HERE / 'web' / 'index.php').read_text(encoding='utf-8')
api = (HERE / 'web' / 'isemon-api.php').read_text(encoding='utf-8')
ini = (HERE / 'web' / '.user.ini').read_text(encoding='utf-8')
vhost = (HERE / 'deploy' / 'nginx-isemon.conf').read_text(encoding='utf-8')
installer = (HERE / 'install.sh').read_text(encoding='utf-8')

print('\nNothing on the page needs PHP to take a body apart')
code = re.sub(r'/\*.*?\*/', '', page, flags=re.S)
ok('no multipart form is sent, and none is read', ('new FormData' in code, '$_FILES' in code,
                                                     '$_POST' in code), (False, False, False))
ok('a database put back is the file itself as the body',
   "body: file, credentials: 'same-origin'" in page
   and "'Content-Type': 'application/octet-stream'" in page
   and "strpos($kind, 'application/octet-stream') === 0" in page
   and 'isemon_take_body(4 * 1024 * 1024 * 1024)' in page)
ok('...written down as it arrives from php://input, never whole in memory',
   "fopen('php://input', 'rb')" in api and 'fread($in, 1048576)' in api)
ok('the page\'s own directory: PHP takes no body apart, no upload progress',
   all(re.search(r'(?m)^%s\s*=\s*%s\s*$' % (k, v), ini) is not None for k, v in
       (('enable_post_data_reading', 'Off'), (r'session\.upload_progress\.enabled', '0'),
        (r'session\.use_strict_mode', '1'))))
ok('...and what was there before stays', 'upload_max_filesize = 4G' in ini
   and 'post_max_size = 4G' in ini)

print('\nThe web server')
ok('the vhost this ships refuses a multipart body, whatever its case',
   'if ($http_content_type ~* "multipart") { return 403; }' in vhost)

print('\nThe installer, on a vhost of the site\'s own')
ok('puts the rule in on an upgrade and on an install that finds one',
   installer.count('nginx_php2shell_guard') == 3 and 'php2shell_said' in installer)
func = re.search(r'(?ms)^nginx_php2shell_guard\(\) \{.*?^\}', installer).group(0)
work = Path(tempfile.mkdtemp(prefix='fixes218-'))
old = work / 'isemon.conf'
old.write_text('server {\n    listen 443 ssl;\n    client_max_body_size 4g;\n'
               '    if ($request_method !~ ^(GET|HEAD|POST)$) { return 405; }\n'
               '    location / { }\n}\n')
fake = work / 'bin'
fake.mkdir()
(fake / 'nginx').write_text('#!/bin/bash\nexit ${NGINX_SAYS:-0}\n')
(fake / 'nginx').chmod(0o755)
script = ('good(){ echo "GOOD $*"; }; warn(){ echo "WARN $*"; }; note(){ :; }\n'
          'systemctl(){ :; }\nNGINX_CONF=%s; DRY_RUN=""\n%s\nnginx_php2shell_guard\n'
          % (old, func))
env = dict(os.environ, PATH='%s:%s' % (fake, os.environ.get('PATH', '')))
said = subprocess.run(['bash', '-c', script], capture_output=True, text=True, env=env).stdout
text = old.read_text()
ok('added once, after the line refusing other methods, with the one before kept',
   (text.count('~* "multipart"'), text.index('multipart') > text.index('$request_method'),
    Path(str(old) + '.before-php2shell').exists(), 'GOOD' in said), (1, True, True, True))
said = subprocess.run(['bash', '-c', script], capture_output=True, text=True, env=env).stdout
ok('...and not again', (old.read_text().count('~* "multipart"'), 'refuses multipart' in said),
   (1, True))
old.write_text('server {\n    listen 443 ssl;\n    location / { }\n}\n')
before = old.read_text()
env['NGINX_SAYS'] = '1'
said = subprocess.run(['bash', '-c', script], capture_output=True, text=True, env=env).stdout
ok('a vhost nginx would not read with it is put back as it was, and said',
   (old.read_text() == before, 'put back' in said), (True, True))
shutil.rmtree(str(work), ignore_errors=True)

print('\nWhat an administrator is told')
ok('the PHP running the page says of itself whether it is fixed and guarded',
   'function isemon_php_safety(): array' in api and "'8.4' => '8.4.27'" in api
   and "'8.2' => '8.2.35'" in api and "'8.5' => '8.5.12'" in api and "'8.3' => '8.3.36'" in api)
ok('...said only to an administrator, in the header, while it is not fixed',
   "($me && ($me['role'] ?? '') === 'fulladmin')" in page and 'id="phpsafety"' in page
   and 'if (s.patched) return;' in page)
php = shutil.which('php')
if php:
    run = subprocess.run([php, '-d', 'enable_post_data_reading=Off', '-d',
                          'session.upload_progress.enabled=0', '-r',
                          'require "%s"; echo json_encode(isemon_php_safety());'
                          % (HERE / 'web' / 'isemon-api.php')],
                         capture_output=True, text=True)
    out = run.stdout.strip().splitlines()[-1] if run.stdout.strip() else ''
    ok('...and on this machine\'s PHP it reads', '"guarded":true' in out, True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
