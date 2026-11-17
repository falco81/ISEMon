#!/usr/bin/env python3
"""1.10.361: the pages follow an upgrade that restarts them (the upgrade-ui kit).

Root writes how far an upgrade is into WEB_DIR/.upgrade.json - the helper for
one from the pages, install.sh for one run by hand - and PHP reads it off
disk while the daemon, nginx and php-fpm restart: a 503 that says
`upgrading` rather than "not answering", ?api=upgrade-state without the
daemon, the status with it, healthz "maintenance", the sign-in page with the
band. With no upgrade, everything is as it was.

    ./test/fixes361_upgrade_ui.py
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
TREE = HERE.parent
PASS = FAIL = 0


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


folder = Path(tempfile.mkdtemp(prefix='isemon-361-'))
for k in ('http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY'):
    os.environ.pop(k, None)

print('root\'s helper tells the pages')
web = folder / 'web'
web.mkdir()
os.environ['ISEMON_WEB_DIR'] = str(web)
sys.path.insert(0, str(TREE / 'deploy'))
import isemon_upgrade as up                          # noqa: E402

up.FROM_VERSION[0] = '1.10.360'
up.pages_tell({'id': 'u1', 'state': 'running', 'version': '1.10.361', 'by': 'admin',
               'downgrade': False, 'at': time.time(),
               'progress': {'pct': 52, 'words': 'the database drivers', 'step': 5, 'total': 8,
                            'began': time.time() - 40}})
got = json.loads((web / '.upgrade.json').read_text())
ok('running, step 5 of 8, as the kit says it',
   (got['state'], got['part'], got['parts'], got['pct'], got['words'], got['from'],
    got['version']),
   ('running', 5, 8, 52, 'the database drivers', '1.10.360', '1.10.361'))
ok('...readable by the web server (0644)', oct((web / '.upgrade.json').stat().st_mode & 0o777),
   '0o644')
ok('...written whole: no temp file left', sorted(p.name for p in web.iterdir()),
   ['.upgrade.json'])
up.pages_tell({'id': 'u1', 'state': 'failed', 'version': '1.10.361', 'rc': 2, 'at': time.time(),
               'progress': {'pct': 52, 'words': 'install.sh ended with 2', 'step': 5,
                            'total': 8}})
got = json.loads((web / '.upgrade.json').read_text())
ok('failed with why', (got['state'], got['said']),
   ('failed', 'install.sh --upgrade stopped (exit 2)'))
up.pages_tell({'id': 'u1', 'state': 'failed', 'said': 'the package is not signed', 'rc': -1,
               'at': time.time(), 'progress': {}})
ok('...refused: what root said', json.loads((web / '.upgrade.json').read_text())['said'],
   'the package is not signed')
up.pages_tell({'id': 'u1', 'state': 'something', 'at': time.time()})
ok('a state that is not one of the three is not written',
   json.loads((web / '.upgrade.json').read_text())['state'], 'failed')
gone = folder / 'gone'
up.WEB_DIR = str(gone)
up.pages_tell({'id': 'u1', 'state': 'running', 'at': time.time(), 'progress': {}})
ok('no web folder (--no-web): nothing, and no error', gone.exists(), False)
up.WEB_DIR = str(web)
src = (TREE / 'deploy' / 'isemon_upgrade.py').read_text()
ok('every status.json written tells the pages too',
   'pages_tell(fields)' in src.split('def status(', 1)[1][:400])

print('\ninstall.sh run by hand tells the pages itself')
sh = (TREE / 'install.sh').read_text()
block = sh[sh.index('UP_STEPS=8\n'):sh.index('# Root\'s half of what the pages may ask')]
script = folder / 't.sh'
script.write_text('set -euo pipefail\n' + block + '''
WITH_WEB=1; WEB_DIR="$1"; VERSION=1.10.361; DRY_RUN=""
UPG_FROM=1.10.360; UPG_STARTED=$(date +%s); UPG_TELL=1
trap 'upgrade_ended $?' EXIT
progress 3 'where the "database" settings \\ are written'
cp "$WEB_DIR/.upgrade.json" "$WEB_DIR/seen.json"
[[ "$2" == fail ]] && false
exit 0
''')
web2 = folder / 'web2'
web2.mkdir()
r = subprocess.run(['bash', str(script), str(web2), 'ok'], capture_output=True, text=True)
seen = json.loads((web2 / 'seen.json').read_text())
ok('a step: running, its words without quotes or backslashes',
   (seen['state'], seen['part'], seen['words'], seen['from'], seen['by']),
   ('running', 3, 'where the database settings  are written', '1.10.360',
    'root on the command line'))
end = json.loads((web2 / '.upgrade.json').read_text())
ok('...its end: done, 100 %', (r.returncode, end['state'], end['pct']), (0, 'done', 100))
r = subprocess.run(['bash', str(script), str(web2), 'fail'], capture_output=True, text=True)
end = json.loads((web2 / '.upgrade.json').read_text())
ok('a run that stops: failed, with the exit code and the step it was at',
   (r.returncode != 0, end['state'], end['part'], 'exit 1' in end['said']),
   (True, 'failed', 3, True))
ok('...the code it stopped with kept', r.returncode, 1)
ok('a run from the pages leaves it to root\'s helper',
   '[[ -z "${ISEMON_UPGRADE_FROM_PAGES:-}" ]] && upgrade_tell running' in sh)
start = sh[sh.index('if [[ -n "$DO_UPGRADE" ]]; then'):]
start = start[:start.index('progress 1 "the packages isemon uses"')]
ok('...and so does --dry-run', '-z "$DRY_RUN"' in start and 'UPG_TELL=1' in start)
ok('stopped with Ctrl-C, a hang-up or a kill: failed, never running for ever',
   all(x in start for x in ("trap 'upgrade_ended $?' EXIT", "trap 'exit 130' INT",
                            "trap 'exit 129' HUP", "trap 'exit 143' TERM")))
ok('the page\'s own counting of install.sh\'s steps unchanged',
   "printf '@@progress %d/%d %s\\n'" in sh and sh.count('    progress ') >= 8)
r = subprocess.run(['bash', '-n', str(TREE / 'install.sh')], capture_output=True)
ok('install.sh reads', r.returncode, 0)

print('\nnginx never serves it')
conf = (TREE / 'deploy' / 'nginx-isemon.conf').read_text()
ok('dot names are refused', 'location ~ /\\.        { deny all; }' in conf)
ok('...and no regex before it serves a .json', conf.index('location ~ /\\.')
   > conf.index('location ~ \\.php$') and '\\.json' not in conf)

print('\nPHP reads it off disk')
site = folder / 'site'
shutil.copytree(str(TREE / 'web'), str(site))
s = socket.socket()
s.bind(('127.0.0.1', 0))
dead = s.getsockname()[1]
s.close()
api = (site / 'isemon-api.php').read_text().split('\n')
tok = folder / 'tok'
tok.write_text('x' * 40 + '\n')
api = ['const ISEMON_PORT    = %d;' % dead if line.startswith('const ISEMON_PORT ') else
       ("const ISEMON_TOKEN   = '%s';" % tok if line.startswith('const ISEMON_TOKEN ') else line)
       for line in api]
(site / 'isemon-api.php').write_text('\n'.join(api))
UP = site / '.upgrade.json'


def tell(state, at=None, **more):
    now = time.time()
    data = dict({'state': state, 'id': 'k1', 'version': '1.10.361', 'from': '1.10.360',
                 'by': 'admin on the pages', 'part': 7, 'parts': 8, 'pct': 84,
                 'words': 'restarting isemon', 'started': now - 60,
                 'at': now if at is None else at, 'said': '', 'downgrade': False}, **more)
    UP.write_text(json.dumps(data))


def php_read(full=False):
    r = subprocess.run(['php', '-r', 'require "%s"; echo json_encode(isemon_upgrading(%s));'
                        % (site / 'isemon-api.php', 'true' if full else 'false')],
                       capture_output=True, text=True)
    return json.loads(r.stdout or 'null')


tell('running')
got = php_read()
ok('running: believed', got and got['state'], 'running')
ok('...nobody signed in: no version, nobody, no why',
   [k for k in ('version', 'from', 'by', 'said', 'id') if k in (got or {})], [])
ok('...signed in: all of it', (php_read(True) or {}).get('version'), '1.10.361')
tell('running', at=time.time() - 31 * 60)
ok('running, not heard of for half an hour: not believed', php_read(), None)
tell('done', at=time.time() - 9 * 60)
ok('done nine minutes ago: believed', (php_read() or {}).get('state'), 'done')
tell('done', at=time.time() - 11 * 60)
ok('...eleven minutes ago: not', php_read(), None)
tell('running', at=time.time() + 3600)
ok('from the future: not believed', php_read(), None)
tell('upgrading')
ok('a state that is not one of the three: none', php_read(), None)
tell('running', words='bad\x1b[31m\x00words', version='1.10.361; rm -rf /')
got = php_read(True)
ok('control characters taken out, a version that is not one dropped',
   ((got or {}).get('words'), (got or {}).get('version')), ('bad [31m words', ''))
UP.write_text('{not json')
ok('a file that does not read: none', php_read(), None)

port = 19361
php = subprocess.Popen(['php', '-S', '127.0.0.1:%d' % port, '-t', str(site)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(0.8)


def get(path):
    try:
        with urllib.request.urlopen('http://127.0.0.1:%d/%s' % (port, path), timeout=20) as a:
            return a.status, a.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


try:
    UP.unlink()
    st, body = get('?api=status')
    ok('no upgrade, the daemon away: as it always was',
       (st, json.loads(body).get('error')), (503, 'the daemon is not answering — is isemon.service running?'))
    st, body = get('healthz.php')
    ok('...healthz: not answering', (st, body.strip()), (503, 'the daemon is not answering'))
    st, body = get('')
    ok('...the sign-in page: the red box, no band',
       ('Nobody can sign in until' in body, 'id="in-upband"' in body), (True, False))
    st, body = get('?api=upgrade-state')
    ok('...upgrade-state: none, the daemon away', (st, json.loads(body)), (200, {'ok': True, 'upgrading': None, 'api': False}))
    tell('running')
    st, body = get('?api=status')
    d = json.loads(body)
    ok('being upgraded: 503 that says so', (st, d.get('error'), d['upgrading']['state']),
       (503, 'being upgraded', 'running'))
    ok('...without the version (nobody known)', 'version' in d['upgrading'], False)
    st, body = get('?api=upgrade-state')
    d = json.loads(body)
    ok('upgrade-state without the daemon', (st, d['upgrading']['part'], d['api']), (200, 7, False))
    ok('...nobody signed in: no version', 'version' in d['upgrading'], False)
    st, body = get('healthz.php')
    ok('healthz: maintenance, not down', (st, body.strip()), (503, 'maintenance'))
    st, body = get('healthz.php?json=1')
    ok('...as JSON', (json.loads(body)['maintenance'], json.loads(body)['said']), (True, 'maintenance'))
    st, body = get('')
    ok('the sign-in page: the band', ('id="in-upband"' in body, 'step 7 of 8' in body), (True, True))
    ok('...not "not answering", not "no account"',
       ('Nobody can sign in until' in body, 'no account on this machine yet' in body), (False, False))
    band = body[body.index('id="in-upband"'):]
    band = band[:band.index('</div>\n      </div>')]
    ok('...no version in it', ('1.10.361' in band, '1.10.360' in band, 'admin' in band),
       (False, False, False))
    ok('...asks every two seconds and loads again', "fetch('?api=upgrade-state'" in body
       and 'location.reload()' in body)
    tell('failed', said='install.sh --upgrade stopped (exit 1)')
    st, body = get('')
    ok('failed, the daemon away: the band in red, and the red box beside it',
       ('upband failed' in body, 'Nobody can sign in until' in body), (True, True))
    st, body = get('?api=status')
    ok('...and API calls the old 503 - nothing is running', json.loads(body).get('upgrading'), None)
    (site / '.upgrade.json').write_text('')
finally:
    php.terminate()

print('\nThe page')
page = (TREE / 'web' / 'index.php').read_text()
ok('the band under the header', '<div id="upband" class="upband" hidden></div>' in page)
ok('a 503 saying upgrading is not a fault', 'if (r.status === 503 && data && data.upgrading)' in page)
ok('...no red box while it is expected', 'if (e && (e.upgrading || e.upgradeAway)) return;' in page)
ok('...no "not answering" bar either', 'if (upgradeExpected() || (e && (e.upgrading || e.upgradeAway)))' in page)
ok('asked every two seconds, falling back to upgrade-state',
   'setInterval(upgradePoll, 2000)' in page and "fetch('?api=upgrade-state'" in page)
ok('loaded again once, never over changes not saved',
   "sessionStorage.getItem('isemon.upg.loaded')" in page and 'UPG.stay = true' in page)
ok('a failure hidden for that upgrade only', "localStorage.setItem('isemon.upg.hide', hideKey)" in page)
ok('the upgrade pane goes on drawing how far, from the file',
   'UP.last.run.progress = {pct: upgradePercent(UPG.u)' in page)

print('\n%d ok, %d failed' % (PASS, FAIL))
shutil.rmtree(folder, ignore_errors=True)
sys.exit(1 if FAIL else 0)
