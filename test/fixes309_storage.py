#!/usr/bin/env python3
"""1.10.309: Settings -> Disk and logs. What fills the disks: the logs that
arrive over syslog folder by folder and whether logrotate takes every one,
inside the database each table and index, and what looks wrong with the
steps that put it right.

    ./test/fixes309_storage.py
"""
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
import isemon                                        # noqa: E402

PASS = FAIL = 0
G = 1024 ** 3


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
    with open(str(p), 'wb') as h:
        h.truncate(int(size))
    t = time.time() - age_days * 86400
    os.utime(str(p), (t, t))


page = (ROOT / 'web' / 'index.php').read_text()
src = (ROOT / 'isemon.py').read_text()
work = Path(tempfile.mkdtemp(prefix='isemon-309-'))
try:
    state = work / 'state'
    state.mkdir()
    for k, v in dict(STATE_DIR=state, DB_FILE=state / 'd.db', BACKUP_DIR=state / 'b',
                     DUMP_DIR=state / 'dumps', RUN_DIR=state, LOG_DIR=state,
                     CONFIG_FILE=state / 'config.json', _LOG_PATH=state / 'd.log',
                     TOKEN_FILE=state / 'token').items():
        setattr(isemon, k, v)
    remote = work / 'remote'
    isemon.CONFIG.clear()
    isemon.CONFIG.update(isemon.DEFAULTS)
    isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0, 'ise': 1, 'ise_paths': [str(remote / 'ise1')]})
    (state / 'config.json').write_text(json.dumps({'db_engine': 'sqlite'}))
    store = isemon.Storage(isemon.DB_FILE)

    print('Reading the files of logrotate')
    lrd = work / 'logrotate.d'
    lrd.mkdir()
    (work / 'logrotate.conf').write_text('weekly\nrotate 4\ncreate\ninclude /etc/logrotate.d\n')
    (lrd / 'remote-logs').write_text(
        '# the ones listed\n%s/ise1/*.log\n%s/blacklistmt/*.log\n{\n    daily\n    rotate 30\n'
        '    compress\n    delaycompress\n    create 0640 root isemon\n    sharedscripts\n'
        '    postrotate\n        /usr/bin/systemctl reload rsyslog { not a stanza }\n'
        '    endscript\n}\n' % (remote, remote))
    (lrd / 'remote-dc').write_text('%s/dc10/*.log {\n    daily\n    rotate 30\n}\n' % remote)
    (lrd / 'nginx').write_text('/var/log/nginx/*.log {\n daily\n rotate 14\n}\n')
    (lrd / 'old.rpmsave').write_text('%s/*/*.log {\n daily\n}\n' % remote)
    isemon.STORE_LOG_ROOTS[:] = [str(remote)]
    isemon.STORE_LOGROTATE[:] = [str(work / 'logrotate.conf'), str(lrd)]
    lr = isemon.store_logrotate()
    names = [os.path.basename(f['file']) for f in lr['files']]
    ok('the main file and the folder, a package\'s leftover (.rpmsave) not',
       names, ['logrotate.conf', 'nginx', 'remote-dc', 'remote-logs'])
    one = next(f for f in lr['files'] if f['file'].endswith('remote-logs'))['stanzas']
    ok('a stanza of several lines of patterns, a brace inside its script not one',
       (len(one), len(one[0]['patterns']), one[0]['opts'].get('every'), one[0]['opts'].get('rotate'),
        one[0]['opts'].get('compress')), (1, 2, 'daily', '30', True))
    ok('the defaults of the main file', (lr['defaults'].get('every'), lr['defaults'].get('rotate')),
       ('weekly', '4'))
    ok('a glob does not cross a slash, as glob(3) does not',
       (isemon.store_glob_match('/v/r/*.log', '/v/r/a/b.log'),
        isemon.store_glob_match('/v/r/*/*.log', '/v/r/a/b.log'),
        isemon.store_glob_match('/v/r/a/*.log', '/v/r/a/%FTD-6-302014.log')), (False, True, True))
    ok('how long copies are kept', (isemon.store_keep_days({'every': 'daily', 'rotate': '30'}, {}),
                                    isemon.store_keep_days({'rotate': '2'}, {'every': 'weekly'}),
                                    isemon.store_keep_days({'every': 'daily', 'rotate': '30',
                                                            'maxage': '7'}, {})), (30, 14, 7))
    ok('what is a copy and what is live',
       [bool(isemon.STORE_ROTATED.search(n)) for n in
        ('a.log', 'a.log-20261106', 'a.log.1', 'a.log.2.gz', 'detail-20261106', 'a.log-2026110613.xz',
         'WinSecurity.log', '%FTD-6-302014.log')],
       [False, True, True, True, True, True, False, False])

    print('\nThe folders, as on the install that filled its disk')
    for n, size in (('%FTD-6-302014.log', 65 * G), ('%FTD-6-302013.log', 63 * G),
                    ('%FTD-1-103001.log', 107)):
        put(remote / '192.168.252.42' / n, size)
    put(remote / 'ise1' / 'CISE_Failed_Attempts.log', 30 * 1024 ** 2)
    put(remote / 'ise1' / 'CISE_Failed_Attempts.log-20261106', 300 * 1024 ** 2, 0.3)
    put(remote / 'ise1' / 'CISE_Failed_Attempts.log-20261105.gz', 15 * 1024 ** 2, 1.3)
    put(remote / 'dc10' / 'WinSecurity.log', 2.5 * G)
    put(remote / 'dc10' / 'WinSecurity.log-20261106', 5.6 * G, 0.4)
    put(remote / 'dc10' / 'WinSecurity.log-20261101', 5 * G, 5)
    out = isemon.storage_health(store, fresh=True)
    by = {f['name']: f for f in out['logs']}
    ok('biggest folder first', [f['name'] for f in out['logs']], ['192.168.252.42', 'dc10', 'ise1'])
    fw = by['192.168.252.42']
    ok('the firewall\'s folder: three live files, none taken by logrotate',
       (fw['live'], fw['uncovered_n'], fw['covered_by'], fw['biggest_live']['name']),
       (3, 3, [], '%FTD-6-302014.log'))
    ok('the ISE folder: taken by remote-logs, kept 30 days, read by isemon',
       ([os.path.basename(c['file']) for c in by['ise1']['covered_by']], by['ise1']['keep_days'],
        by['ise1']['read_by'], by['ise1']['uncovered_n']), (['remote-logs'], 30, ['ISE'], 0))
    ok('...how much a day it grows: yesterday\'s copy', (by['ise1']['a_day'], by['ise1']['a_day_how']),
       (300 * 1024 ** 2, 'yesterday'))
    ok('the domain controller\'s copy older than three days left unpacked: counted',
       by['dc10']['old_raw_bytes'], 5 * G)
    probs = {p['key']: p for p in out['problems']}
    un = probs.get('unrotated')
    ok('the folders nothing rotates are trouble, first among the logs',
       (un and un['level'], un and un['folders']), ('crit', ['192.168.252.42']))
    text = un['fix'][0]['text']
    ok('...with a logrotate file for them, under a name not taken',
       (un['fix'][0]['file'].endswith('/remote-isemon'), '%s/192.168.252.42/*.log' % remote in text,
        'create 0640 root ' in text, 'rotate 2' in text, 'postrotate' in text,
        'systemctl reload rsyslog' in text), (True,) * 6)
    ok('...and how to check it, rotate it now and let the copies go',
       ('duplicate' in un['fix'][1]['text'], un['fix'][2]['text'].startswith('logrotate -f '),
        '-delete' in un['fix'][3]['text']), (True, True, True))
    ok('the unpacked copies said, with the command that packs them',
       ('raw-copies' in probs, 'gzip' in (probs.get('raw-copies') or {'fix': [{'text': ''}]})['fix'][0]['text']),
       (True, True))
    ok('only the logrotate files that name these folders are listed',
       sorted(os.path.basename(f['file']) for f in out['logrotate']), ['remote-dc', 'remote-logs'])
    ok('a minute kept: asked again, the same answer', isemon.storage_health(store).get('cached'), True)

    print('\nTwo files taking one folder')
    (lrd / 'remote-more').write_text('%s/ise1/*.log {\n daily\n}\n' % remote)
    out = isemon.storage_health(store, fresh=True)
    dup = [p for p in out['problems'] if p['key'].startswith('dupe:')]
    ok('said as trouble: logrotate refuses the whole run over it',
       (len(dup), dup and dup[0]['level'], dup and 'WHOLE run' in dup[0]['says']), (1, 'crit', True))
    (lrd / 'remote-more').unlink()

    print('\nA folder rotated, but a big live file and no copy for days')
    put(remote / 'dc10' / 'WinSecurity.log', 9 * G)
    for x in (remote / 'dc10').glob('WinSecurity.log-*'):
        os.utime(str(x), (time.time() - 9 * 86400, time.time() - 9 * 86400))
    out = isemon.storage_health(store, fresh=True)
    ok('said: taken by logrotate but not being rotated',
       any(p['key'].startswith('stuck:') and 'dc10' in p['title'] for p in out['problems']), True)

    print('\nThe disk, and inside the database')
    d0 = out['disks'][0]
    ok('a disk with what of ours is on it, and the rest',
       ({'logs', 'db', 'dumps', 'backups'} <= {p['key'] for p in d0['parts']}, 'other' in d0,
        d0['total'] > 0), (True, True, True))
    ok('the tables of the database (SQLite: by its dbstat), biggest first',
       bool(out['db']['tables']) and out['db']['tables'][0]['total']
       >= out['db']['tables'][-1]['total'], True)
    ok('a table split by day said as one, by its kind of day',
       (isemon.STORE_PART_SPLIT.search('fw_events_p20261105_c1').group(2),
        'fw_events_p20261105_c1'[:isemon.STORE_PART_SPLIT.search('fw_events_p20261105_c1').start()]),
       ('1', 'fw_events'))

    print('\nWhat fills the disk soonest')
    disks = [{'mount': '/', 'total': 571 * G, 'used': 508 * G, 'free': 38 * G, 'share': 94.0,
              'parts': [{'key': 'logs', 'label': 'logs that arrive over syslog', 'bytes': 418 * G}],
              'other': 0}]
    logs = [dict(by['ise1'], a_day=45 * G, uncovered_n=1)]
    got = isemon.store_problems(disks, logs, lr, {'tables': [], 'indexes': []}, {'a_day': 0}, {})
    ok('94 % full and filling in a day: trouble, said with what fills it',
       (got[0]['level'], 'full' in got[0]['title'], 'logs that arrive over syslog' in got[0]['says']),
       ('crit', True, True))
    ok('...how many days it holds, on the disk', disks[0]['days_left'], 0)
    steady = dict(by['ise1'], a_day=45 * G, oldest=time.time() - 31 * 86400)
    filling = dict(by['ise1'], a_day=12 * G, oldest=time.time() - 2 * 86400)
    disks2 = [dict(disks[0], free=380 * G, share=29.0)]
    got = isemon.store_problems(disks2, [steady, filling], lr, {'tables': [], 'indexes': []},
                                {'a_day': 0}, {})
    ok('a log rotated and let go of after its copies: as big tomorrow - nothing it writes counted; '
       'one still filling its copies: a packed copy a day', (steady['lasting'], filling['lasting'],
                                                            disks2[0]['days_left']),
       (0, 1 * G, 380))
    ok('...so 380 GB free is not "full in 13 days"', [p['key'] for p in got if p['key'].startswith('disk:')], [])
    big = {'tables': [{'name': 'fw_events', 'kind': 1, 'total': 37 * G, 'dead': 0, 'live': 1},
                      {'name': 'fw_events', 'kind': 0, 'total': 23 * G, 'dead': 0, 'live': 1}],
           'indexes': [{'name': 'x', 'table': 'fw_events_p20261105_c1', 'group': 'fw_events',
                        'kind': 1, 'bytes': 2 * G, 'scans': 0}]}
    got = {p['key']: p for p in isemon.store_problems([], [], lr, big, {}, {})}
    ok('the sessions let through as most of the database: the setting that keeps them said',
       ('fw-allowed' in got, got.get('fw-allowed', {}).get('fix', [{}])[0].get('pane')), (True, 'fwlog'))
    ok('indexes not used yet: worth knowing, not trouble', got.get('unused-indexes', {}).get('level'),
       'info')
finally:
    shutil.rmtree(str(work), ignore_errors=True)

print('\nThe page')
ok('a pane of its own under Data, for a full admin',
   ('data-pane="storage"' in page and 'id="pane-storage"' in page,
    "if (name === 'storage') loadStorage(false);" in page), (True, True))
ok('relayed to the daemon as a read, the daemon asking for a full admin',
   ("'storage'        => '/api/storage'," in page,
    "if path == '/api/storage':\n            # Settings" in src), (True, True))
ok('a fix with a file: the file, or one command that writes it',
   ("'one command that writes it'" in page, "\"cat > \" + f.file + \" <<'EOF'\\n\"" in page),
   (True, True))
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
