#!/usr/bin/env python3
"""1.10.310: Settings -> Disk and logs puts it right by root's helper - a
logrotate file of isemon's own for the folders nothing rotates, checked with
logrotate before and after and put back if it says no; old copies packed.

    ./test/fixes310_logfix.py
"""
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
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


def put(p, size, age_days=0.0):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b'x' * int(size))
    t = time.time() - age_days * 86400
    os.utime(str(p), (t, t))


work = Path(tempfile.mkdtemp(prefix='isemon-310-'))
try:
    state = work / 'state'
    (state / 'web').mkdir(parents=True)
    remote = work / 'remote'
    lrd = work / 'logrotate.d'
    lrd.mkdir()
    conf = work / 'logrotate.conf'
    conf.write_text('weekly\nrotate 4\ninclude %s\n' % lrd)
    fake = work / 'logrotate'
    # What logrotate says: a duplicate where the folder "twice" is in two files.
    fake.write_text('#!/bin/sh\n'
                    'if [ "$1" = "-d" ]; then\n'
                    '  n=$(grep -l "/twice/" %s/* 2>/dev/null | wc -l)\n'
                    '  [ "$n" -gt 1 ] && echo "error: %s/twice/a.log:1 duplicate log entry for %s/twice/a.log"\n'
                    '  exit 0\nfi\n'
                    'if [ "$1" = "-f" ]; then echo rotated > %s/rotated; exit 0; fi\n'
                    % (lrd, remote, remote, work))
    fake.chmod(0o755)
    ENV = dict(os.environ, ISEMON_STATE=str(state), ISEMON_WEB_NO_SERVICES='1',
               ISEMON_REMOTE_LOGS=str(remote), ISEMON_LOGROTATE_D=str(lrd),
               ISEMON_LOGROTATE_CONF=str(conf), ISEMON_LOGROTATE=str(fake), ISEMON_GROUP='root',
               ISEMON_NGINX_CONF=str(work / 'none.conf'))
    HELPER = ROOT / 'deploy' / 'isemon_web.py'

    def ask(req, fresh=True):
        if fresh and 'at' not in req:
            req = dict(req, at=time.time())
        (state / 'web' / 'logfix.ask').write_text(json.dumps(req))
        got = subprocess.run(['python3', '-I', str(HELPER)], env=ENV, capture_output=True,
                             text=True)
        if got.returncode:
            print(got.stderr)
        return json.loads((state / 'web' / 'logfix.json').read_text())

    for n in ('fw1', 'fw2', 'twice'):
        put(remote / n / 'a.log', 10)
    (remote / 'elsewhere').mkdir()
    os.symlink(str(remote / 'elsewhere'), str(remote / 'linked'))
    mine = lrd / 'remote-isemon'

    print('Root\'s helper: logrotate for the folders nothing rotates')
    got = ask({'do': 'cover', 'folders': ['fw1'], 'keep': 2})
    text = mine.read_text() if mine.exists() else ''
    ok('written, isemon\'s own, root\'s 0644', (got['ok'], '# Written by isemon' in text,
                                               stat.S_IMODE(mine.stat().st_mode)), (True, True, 0o644))
    ok('...one stanza for the folder, as it was asked: two copies, compressed, made for the daemon',
       ('%s/fw1/*.log\n{' % remote in text, 'rotate 2' in text, '    compress' in text,
        'create 0640 root root' in text, 'systemctl reload rsyslog' in text), (True,) * 5)
    got = ask({'do': 'cover', 'folders': ['fw2'], 'keep': 2, 'rotate_now': True})
    text = mine.read_text()
    ok('asked again for another: added to it, the first kept', ('%s/fw1/*.log' % remote in text,
                                                               '%s/fw2/*.log' % remote in text,
                                                               got['data']['added']), (True, True, ['fw2']))
    ok('...and rotated at once, that file alone', (got['data']['rotated'], (work / 'rotated').exists()),
       (True, True))
    for bad in (['../etc'], ['fw1/../../etc'], ['linked'], ['nothere'], [], 'fw1', ['a' * 200]):
        r = ask({'do': 'cover', 'folders': bad})
        ok('refused: %r' % (bad if not isinstance(bad, list) or not bad or len(bad[0]) < 40 else 'long'),
           r['ok'], False)
    ok('nothing written by any of them', '../' not in mine.read_text() and 'linked' not in mine.read_text())
    r = ask({'do': 'cover', 'folders': ['fw1'], 'at': time.time() - 3600}, fresh=False)
    ok('asked an hour ago: not done', (r['ok'], 'too long ago' in r.get('said', '')), (False, True))

    print('\nWhat logrotate says decides')
    (lrd / 'remote-other').write_text('%s/twice/*.log {\n daily\n}\n' % remote)
    was = mine.read_text()
    r = ask({'do': 'cover', 'folders': ['twice']})
    ok('a folder another file takes already: refused by root\'s own look, before logrotate (1.10.311)',
       (r['ok'], 'taken by' in r.get('said', '') and 'remote-other' in r.get('said', '')), (False, True))
    ok('...and the file put back exactly as it was', mine.read_text(), was)
    (lrd / 'remote-other').unlink()
    mine.unlink()
    (lrd / 'remote-other').write_text('%s/twice/*.log {\n daily\n}\n' % remote)
    r = ask({'do': 'cover', 'folders': ['twice']})
    ok('...where there was none before, none left after', (r['ok'], mine.exists()), (False, False))
    (lrd / 'remote-other').unlink()
    print('\nWhat a site\'s own logrotate files are like (1.10.311)')
    for n in ('ftd9.example', 'dc77', 'hidden', 'odd', 'deep'):
        put(remote / n / 'a.log', 10)
    put(remote / 'hidden' / '.log', 10)
    put(remote / 'odd' / 'detail-today', 10)
    put(remote / 'deep' / 'sub' / 'b.log', 10)
    (lrd / 'remote-ftd').write_text('%s/ftd*/*.log\n%s/ftd*/.log\n{\n daily\n maxsize 1G\n'
                                    ' dateformat -%%Y%%m%%d-%%s\n rotate 100\n maxage 30\n}\n'
                                    % (remote, remote))
    dc = work / 'logrotate.dc.conf'
    dc.write_text('%s/dc77/*.log {\n hourly\n}\n' % remote)
    for n, why in (('ftd9.example', 'remote-ftd'), ('dc77', 'logrotate.dc.conf'),
                   ('odd', 'not named *.log'), ('deep', 'folders in it')):
        r = ask({'do': 'cover', 'folders': [n]})
        ok('%s: refused (%s)' % (n, why), (r['ok'], why in r.get('said', '')), (False, True))
    ok('...nothing written for any of them', mine.exists(), False)
    r = ask({'do': 'cover', 'folders': ['hidden']})
    text = mine.read_text() if mine.exists() else ''
    ok('a folder with a log named .log: that one named on a line of its own, since *.log does not take it',
       (r['ok'], '%s/hidden/*.log' % remote in text, '%s/hidden/.log' % remote in text), (True, True, True))
    mine.unlink()
    (lrd / 'remote-ftd').unlink()
    dc.unlink()
    for n in ('ftd9.example', 'dc77', 'hidden', 'odd', 'deep'):
        shutil.rmtree(str(remote / n))
    mine.write_text('# somebody\'s own\n/var/log/x/*.log {\n daily\n}\n')
    r = ask({'do': 'cover', 'folders': ['fw1']})
    ok('a remote-isemon somebody else wrote: never touched',
       (r['ok'], 'not written by isemon' in r.get('said', ''), mine.read_text().startswith('# somebody')),
       (False, True, True))
    mine.unlink()
    if shutil.which('logrotate'):
        ENV2 = dict(ENV, ISEMON_LOGROTATE=shutil.which('logrotate'))
        (state / 'web' / 'logfix.ask').write_text(json.dumps(
            {'do': 'cover', 'folders': ['fw1', 'fw2'], 'keep': 2, 'at': time.time()}))
        subprocess.run(['python3', '-I', str(HELPER)], env=ENV2, capture_output=True, text=True)
        r = json.loads((state / 'web' / 'logfix.json').read_text())
        chk = subprocess.run([shutil.which('logrotate'), '-d', str(mine)], capture_output=True,
                             text=True)
        ok('the real logrotate reads the file it writes, with nothing wrong in it',
           (r['ok'], [ln for ln in (chk.stdout + chk.stderr).splitlines() if 'error' in ln.lower()]),
           (True, []))
        mine.unlink()

    print('\nPacking the old copies')
    put(remote / 'fw1' / 'a.log-20261101', 5000, 5)
    put(remote / 'fw1' / 'a.log-20261105', 5000, 1)
    put(remote / 'fw1' / 'a.log.3', 5000, 6)
    put(remote / 'fw1' / 'b.log-20261101.gz', 50, 5)
    r = ask({'do': 'pack', 'folders': ['fw1']})
    names = sorted(os.listdir(str(remote / 'fw1')))
    ok('the copies older than three days packed; yesterday\'s, the live file and a packed one not',
       (r['ok'], r['data']['files'], names),
       (True, 2, ['a.log', 'a.log-20261101.gz', 'a.log-20261105', 'a.log.3.gz', 'b.log-20261101.gz']))

    print('\nThe daemon asks it, only for what its own look offers')
    for k, v in dict(STATE_DIR=state, DB_FILE=state / 'd.db', BACKUP_DIR=state / 'b',
                     DUMP_DIR=state / 'dumps', RUN_DIR=state, LOG_DIR=state,
                     CONFIG_FILE=state / 'config.json', _LOG_PATH=state / 'd.log',
                     TOKEN_FILE=state / 'token').items():
        setattr(isemon, k, v)
    isemon.CONFIG.clear()
    isemon.CONFIG.update(isemon.DEFAULTS)
    isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0})
    (state / 'config.json').write_text(json.dumps({'db_engine': 'sqlite'}))
    store = isemon.Storage(isemon.DB_FILE)
    isemon.STORE_LOG_ROOTS[:] = [str(remote)]
    isemon.STORE_LOGROTATE[:] = [str(conf), str(lrd)]

    class WR(object):
        def helper_there(self):
            return True

        def folder(self):
            return state / 'web'

        def write(self, name, data):
            (state / 'web' / name).write_text(json.dumps(data))
            subprocess.run(['python3', '-I', str(HELPER)], env=ENV, capture_output=True)

        def read(self, name):
            try:
                return json.loads((state / 'web' / name).read_text())
            except (OSError, ValueError):
                return None
    try:
        isemon.storage_fix(store, WR(), {'do': 'cover', 'folders': ['../etc']}, 'boss')
        ok('a folder the look did not offer: refused', False)
    except ValueError:
        ok('a folder the look did not offer: refused', True)
    got = isemon.storage_fix(store, WR(), {'do': 'cover', 'folders': ['fw1', 'fw2', 'twice']}, 'boss')
    ok('the ones it offered: put in by root, said in Events',
       (got['ok'], sorted(got['folders']), 'had root put' in json.dumps(
           [dict(e) for e in store.db.execute('SELECT * FROM events')])),
       (True, ['fw1', 'fw2', 'twice'], True))
    look = isemon.storage_health(store)
    ok('looked at again at once: nothing left that nothing rotates',
       [p['key'] for p in look['problems'] if p['key'] == 'unrotated'], [])
    try:
        isemon.storage_fix(store, WR(), {'do': 'cover'}, 'boss')
        ok('asked again with nothing to do: said so', False)
    except ValueError as e:
        ok('asked again with nothing to do: said so', 'nothing of that' in str(e))

    print('\nA log written a file a day (1.10.311)')
    fm = remote / 'fw.merit.cz'
    for d in range(1, 7):
        put(fm / ('date=2026-11-%02d.log' % d), 100, 6 - d)
    put(fm / 'date=2026-09-20.log-20260921', 5000, 46)
    put(fm / 'date=2026-09-21.log-20260922.gz', 500, 45)
    put(fm / 'date=2026-10-27.log-20261028', 5000, 10)
    put(fm / 'date=2026-11-01.log-20261102', 5000, 4.5)
    put(fm / 'date=2026-11-05.log-20261106', 5000, 1)
    os.symlink(str(work / 'outside.log-20200101'), str(fm / 'link.log-20200101'))
    (work / 'outside.log-20200101').write_text('keep me')
    os.utime(str(work / 'outside.log-20200101'), (time.time() - 99 * 86400,) * 2)
    (lrd / 'remote-logs').write_text('%s/fw.merit.cz/*.log\n{\n    daily\n    dateext\n    rotate 30\n'
                                     '    compress\n    delaycompress\n}\n' % remote)
    look = isemon.storage_health(store, fresh=True)
    pd = next((p for p in look['problems'] if p['key'].startswith('per-day:')), None)
    ok('said: a file a day, its copies never let go of - with what root can do, kept as its file keeps',
       (pd and pd['level'], pd and pd['apply'], pd and 'never lets a copy go' in pd['says']),
       ('warn', {'do': 'dayfix', 'folders': ['fw.merit.cz'], 'keep': 30,
                 'cron': '/etc/cron.daily/isemon-day-logs', 'from': [str(lrd / 'remote-logs')]}, True))
    ok('...not said twice as copies kept unpacked', [p['key'] for p in look['problems']
                                                     if p['key'] == 'raw-copies'], [])
    r = ask({'do': 'age', 'folders': ['fw.merit.cz'], 'keep': 3})
    ok('kept fewer than 7 days: refused', r['ok'], False)
    got = ask({'do': 'age', 'folders': ['fw.merit.cz'], 'keep': 30})['data']
    names = sorted(os.listdir(str(fm)))
    ok('the copies older than its 30 days let go of, the days kept by the page not asked',
       (got['gone'], got['keep'], 'date=2026-09-20.log-20260921' in names,
        'date=2026-09-21.log-20260922.gz' in names), (2, 30, False, False))
    ok('...those older than three days packed, yesterday\'s and every live day file left',
       ('date=2026-10-27.log-20261028.gz' in names, 'date=2026-11-01.log-20261102.gz' in names,
        'date=2026-11-05.log-20261106' in names, sum(1 for n in names if n.endswith('.log'))),
       (True, True, True, 6))
    ok('...and a link among them neither followed nor taken', ((work / 'outside.log-20200101').read_text(),
                                                               os.path.islink(str(fm / 'link.log-20200101'))),
       ('keep me', True))

    print('\nA file a day, for good: out of logrotate, aged by a cron of its own (1.10.316)')
    cron = work / 'cron.daily'
    cron.mkdir()
    ENV['ISEMON_CRON_DAILY'] = str(cron)
    isemon.STORE_DAYLOGS = str(cron / 'isemon-day-logs')
    (lrd / 'remote-logs').write_text('# the ones listed\n%s/isemon/*.log\n%s/fw.merit.cz/*.log\n{\n'
                                     '    daily\n    rotate 30\n    compress\n    delaycompress\n'
                                     '    postrotate\n        /usr/bin/systemctl reload rsyslog\n'
                                     '    endscript\n}\n' % (remote, remote))
    put(remote / 'isemon' / 'systemd.log', 10)
    put(fm / 'date=2026-10-01.log', 100, 36)
    put(fm / 'date=2026-11-03.log', 100, 3)
    put(fm / 'date=2026-10-02.log-20261003', 5000, 35)
    look = isemon.storage_health(store, fresh=True)
    got = isemon.storage_fix(store, WR(), {'do': 'dayfix', 'folders': ['fw.merit.cz'], 'keep': 1}, 'boss')
    lr_text = (lrd / 'remote-logs').read_text()
    ok('its own line out of remote-logs, every other line of it as it was',
       ('fw.merit.cz' in lr_text, '%s/isemon/*.log' % remote in lr_text, 'postrotate' in lr_text,
        '# the ones listed' in lr_text), (False, True, True, True))
    ctext = (cron / 'isemon-day-logs').read_text()
    ok('...and /etc/cron.daily/isemon-day-logs written, 0755, with it and its own 30 days',
       ('fw.merit.cz 30' in ctext, oct(os.stat(str(cron / 'isemon-day-logs')).st_mode & 0o777),
        got['keep'], 'Written by isemon' in ctext), (True, '0o755', 30, True))
    names = sorted(os.listdir(str(fm)))
    ok('...run once at once: older than 30 days let go of, older than two days packed, the newest left',
       ('date=2026-10-01.log' in names, 'date=2026-10-02.log-20261003' in names,
        'date=2026-11-03.log.gz' in names, 'date=2026-11-06.log' in names,
        'date=2026-11-05.log' in names), (False, False, True, True, True))
    ok('...the link left alone', ((work / 'outside.log-20200101').read_text(),
                                  os.path.islink(str(fm / 'link.log-20200101'))), ('keep me', True))
    sh = subprocess.run(['sh', '-n', str(cron / 'isemon-day-logs')], capture_output=True)
    ok('...a script sh reads', sh.returncode, 0)
    look = isemon.storage_health(store, fresh=True)
    fmrow = next(f for f in look['logs'] if f['name'] == 'fw.merit.cz')
    ok('looked at again: aged by the cron, not "nothing rotates it", not a file a day never let go of',
       (fmrow['uncovered_n'], fmrow.get('by_cron'), [p['key'] for p in look['problems']
                                                     if 'fw.merit.cz' in p['key'] or p['key'] == 'unrotated']),
       (0, True, []))
    ok('in Events, as a warning', 'out of' in json.dumps(
        [dict(e) for e in store.db.execute('SELECT * FROM events')]) and 'isemon-day-logs' in json.dumps(
        [dict(e) for e in store.db.execute('SELECT * FROM events')]))
    # Where it cannot be taken out of one folder alone: refused, nothing changed.
    put(remote / 'ftd1.x' / 'date=2026-11-06.log', 10)
    put(remote / 'ftd1.x' / 'date=2026-11-05.log', 10)
    put(remote / 'ftd1.x' / 'date=2026-11-04.log', 10)
    (lrd / 'remote-ftd').write_text('%s/ftd*/*.log\n{\n daily\n}\n' % remote)
    r = ask({'do': 'dayfix', 'folders': ['ftd1.x'], 'keep': 30})
    ok('a folder taken by a pattern for more than it (ftd*): refused, that file as it was',
       (r['ok'], 'pattern for more than it' in r.get('said', ''), (lrd / 'remote-ftd').read_text().count('ftd*')),
       (False, True, 1))
    (lrd / 'remote-ftd').write_text('%s/ftd1.x/*.log\n{\n daily\n}\n' % remote)
    r = ask({'do': 'dayfix', 'folders': ['ftd1.x'], 'keep': 30})
    ok('...its line all a stanza has: refused, as it was', (r['ok'], 'all a stanza' in r.get('said', ''),
                                                           'ftd1.x' in (lrd / 'remote-ftd').read_text()),
       (False, True, True))
    (lrd / 'remote-ftd').unlink()
    dcc = work / 'logrotate.dc.conf'
    dcc.write_text('%s/ftd1.x/*.log {\n hourly\n}\n' % remote)
    r = ask({'do': 'dayfix', 'folders': ['ftd1.x'], 'keep': 30})
    ok('...taken by a configuration of its own (logrotate.dc.conf): refused', (r['ok'], 'not under' in r.get('said', '')),
       (False, True))
    dcc.unlink()
    r = ask({'do': 'dayfix', 'folders': ['isemon'], 'keep': 30})
    ok('a folder with no log named by the day: refused', (r['ok'], 'named by the day' in r.get('said', '')),
       (False, True))
    # logrotate saying something new is wrong after: all of it put back.
    (lrd / 'remote-logs').write_text('%s/isemon/*.log\n%s/ftd1.x/*.log\n{\n daily\n}\n' % (remote, remote))
    was_lr, was_cron = (lrd / 'remote-logs').read_text(), (cron / 'isemon-day-logs').read_text()
    bad = work / 'logrotate-bad'
    bad.write_text('#!/bin/sh\nif [ "$1" = "-d" ] && ! grep -q ftd1.x %s/remote-logs; then '
                   'echo "error: injected after"; fi\nexit 0\n' % lrd)
    bad.chmod(0o755)
    ENV['ISEMON_LOGROTATE'], keep_lr = str(bad), ENV['ISEMON_LOGROTATE']
    r = ask({'do': 'dayfix', 'folders': ['ftd1.x'], 'keep': 30})
    ENV['ISEMON_LOGROTATE'] = keep_lr
    ok('logrotate saying something is wrong after it: refused, remote-logs and the cron as they were',
       (r['ok'], 'injected after' in r.get('said', ''), (lrd / 'remote-logs').read_text() == was_lr,
        (cron / 'isemon-day-logs').read_text() == was_cron), (False, True, True, True))
    (lrd / 'remote-logs').write_text('%s/isemon/*.log\n{\n daily\n}\n' % remote)
    (cron / 'isemon-day-logs').write_text('#!/bin/sh\n# mine\n')
    r = ask({'do': 'dayfix', 'folders': ['ftd1.x'], 'keep': 30})
    ok('an isemon-day-logs somebody else wrote: never touched', (r['ok'], (cron / 'isemon-day-logs').read_text()),
       (False, '#!/bin/sh\n# mine\n'))
finally:
    shutil.rmtree(str(work), ignore_errors=True)

page = (ROOT / 'web' / 'index.php').read_text()
web = (ROOT / 'deploy' / 'isemon_web.py').read_text()
unit = (ROOT / 'deploy' / 'isemon-web.path').read_text()
print('\nThe page and the path unit')
ok('the path unit hands logfix.ask to root', 'PathExists=/var/lib/isemon/web/logfix.ask' in unit)
ok('relayed as a write, for a full admin, with the button on the problem',
   ("'storage'      => '/api/storage'," in page, "box.appendChild(stApply(p.apply))" in page),
   (True, True))
ok('...the folder names in the question made safe as text', "htmlText(ap.folders.join(', '))" in page)
ok('root writes from the names alone, never what the page sent',
   ("def logfix_text(folders, keep):" in web, "r.get('text')" not in web), (True, True))
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
