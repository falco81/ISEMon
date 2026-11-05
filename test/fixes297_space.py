#!/usr/bin/env python3
"""1.10.297: quicker on a big database, and no space taken for nothing.

- acme: what every certificate is is worked out once and kept until a line
  arrives (the header asked for it every half minute); a certificate whose
  last line is older than the newest 50 000 is still there; the tab's day by
  day is counted by the database, and is right past 300 000 lines; a job's
  last line is asked only of the jobs that have not ended; the checks have
  an index of their own; old lines are let go a stride at a time.
- Indexes no query needs, taken away: (ip, ts) of the refusals and the
  sign-ins beside (ip, ts, kind, country); a packet's session; a name.
- SQLite's write-ahead log cut back once checkpointed; halves of copies and
  uploads a stopped daemon left are taken away by the daemon itself; the
  debug switch left on no longer fills the disk.

    ./test/fixes297_space.py
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


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


def iso(ago):
    return time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(time.time() - ago))


work = Path(tempfile.mkdtemp(prefix='isemon-297-'))
try:
    state = work / 'state'
    state.mkdir()
    for k, v in dict(STATE_DIR=state, DB_FILE=state / 'd.db', BACKUP_DIR=state / 'b',
                     DUMP_DIR=state / 'dumps', RUN_DIR=state, LOG_DIR=state,
                     CONFIG_FILE=state / 'config.json', _LOG_PATH=state / 'd.log',
                     TOKEN_FILE=state / 'token').items():
        setattr(isemon, k, v)
    isemon.CONFIG.clear()
    isemon.CONFIG.update(isemon.DEFAULTS)
    isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0, 'acmelog': 1,
                          'acmelog_paths': [str(work / 'acme')]})
    (state / 'config.json').write_text(json.dumps({'db_engine': 'sqlite'}))
    store = isemon.Storage(isemon.DB_FILE)
    daemon = isemon.Daemon(store)

    print('Indexes no query needs')
    for sql in ('CREATE INDEX failed_ip ON failed (ip, ts)',
                'CREATE INDEX passed_ip ON passed (ip, ts)',
                'CREATE INDEX ptr_name ON ptr (name)',
                'CREATE INDEX otp_asked_session ON otp_asked (session)'):
        store.db.execute(sql)
    store.db.close()
    store = isemon.Storage(isemon.DB_FILE)
    have = {r['name'] for r in store.db.execute(
        "SELECT name FROM sqlite_master WHERE type='index'")}
    ok('those an older version made, taken away',
       sorted(have & {'failed_ip', 'passed_ip', 'ptr_name', 'otp_asked_session'}), [])
    ok('...and the wider ones that do their work are there',
       ('failed_ip_ts_kind' in have, 'passed_ip_ts_kind' in have), (True, True))
    ok('acme\'s checks have an index of their own', 'acme_jobs_kind_ts' in have)
    plan = ' '.join(str(r['detail']) for r in store.db.execute(
        'EXPLAIN QUERY PLAN SELECT COUNT(*) FROM failed WHERE ip = ? AND ts >= ?',
        ('192.0.2.1', 0)))
    ok('an address\'s refusals of a window: sought, not read through (%s)' % plan[-60:],
       'SEARCH' in plan and 'USING' in plan)
    ok('the write-ahead log cut back once checkpointed',
       store.db.execute('PRAGMA journal_size_limit').fetchone()[0], 64 * 1024 * 1024)
    daemon = isemon.Daemon(store)

    print('\nacme: certificates')
    lines = []

    def L(ago, tag, **f):
        head = 'level=%s kind=%s node=%s who=acme' % (f.pop('level', 'info'),
                                                      f.pop('kind', 'certificates'),
                                                      f.pop('node', 'acme1'))
        rest = ' '.join('%s=%s' % (k, f[k]) for k in sorted(f))
        lines.append('%s acme %s[1]: %s %s msg=x' % (iso(ago), tag, head, rest))
    L(90 * 86400, 'acme-certs', action='issued', cert='old', result='ok')
    for i in range(30):
        L(3600 + i, 'acme-certs', action='deployed', cert='busy', target='f5', result='ok')
    L(100, 'acme-certs', level='bad', node='acme2', action='deploy', cert='busy', target='f5b',
      result='failed')
    daemon.read_records(lines, kind='acmelog')
    keep = store.ACME_FACTS_LINES
    store.ACME_FACTS_LINES = 10
    store.acme_lines_came()
    names = {c['cert'] for c in store.acme_certificates()}
    ok('a certificate older than the newest lines read: still there', names, {'old', 'busy'})
    store.ACME_FACTS_LINES = keep
    store._acme_gen_at = 0
    first = store.acme_cert_facts()
    ok('...worked out once and kept', store.acme_cert_facts() is first)
    store.acme_lines_came()
    soon = store.acme_cert_facts()
    ok('...but not kept when worked out the moment a line came (its batch may not be in yet)',
       store.acme_cert_facts() is soon, False)
    lines[:] = []
    L(50, 'acme-certs', action='issued', cert='new', result='ok')
    daemon.read_records(lines, kind='acmelog')
    ok('...worked out again once a line arrives',
       'new' in {c['cert'] for c in store.acme_certificates()})
    ok('...and how many want looking at, from the kept one', store.acme_attention(), 1)

    print('\nacme: the tab, counted by the database')
    view = store.acme_view(400)
    n = store.db.execute('SELECT COUNT(*) FROM acme_events WHERE ts >= ?',
                         (view['since'],)).fetchone()[0]
    ok('every line of the period counted', view['sums']['events'], n)
    ok('...each in a day', sum(b['issued'] + b['deployed'] + b['failed'] + b['warn'] + b['other']
                               for b in view['activity']), n)
    ok('...deployed and issued as before', (view['sums']['deployed'], view['sums']['issued'],
                                            view['sums']['deploy_failed']), (30, 2, 1))
    today = view['activity'][-1]
    ok('...the newest on today', today['failed'] + today['issued'] >= 1)
    nodes = {x['node']: x for x in view['nodes']}
    ok('a node\'s last trouble, and none for the node that had none',
       (bool(nodes['acme2']['last_bad']), nodes['acme1']['last_bad']), (True, None))
    ok('how many there are, and the last read', (view['total'] >= n, bool(view['last_read'])),
       (True, True))

    print('\nacme: jobs')
    lines[:] = []
    L(600, 'acme-jobs', kind='job', event='start', job='1', t_ms=0)
    L(590, 'acme-jobs', kind='job', event='step', job='1', t_ms=10)
    L(580, 'acme-jobs', kind='job', event='end', job='1', state='ok', ok=1, took_ms=20000)
    L(500, 'acme-jobs', kind='job', event='start', job='2', t_ms=0)
    L(490, 'acme-jobs', kind='job', event='step', job='2', t_ms=10)
    L(20 * 3600, 'acme-jobs', kind='job', event='start', job='3', t_ms=0)
    L(60, 'acme-jobs', kind='check', event='result', check_id='7', test='https', state='ok', ok=1)
    daemon.read_records(lines, kind='acmelog')
    lines.append('%s acme acme-jobs[1]: level=info kind=job who=acme event=start job=4 t_ms=0 '
                 'msg=x' % iso(400))
    lines.append('%s acme acme-jobs[1]: level=info kind=job node=acme1 who=acme event=start '
                 't_ms=0 msg=x' % iso(400))
    jobs = {j['job']: j for j in store.acme_jobs_list(time.time() - 86400)}
    ok('a job with no node, one with no job: the list still made', '1' in jobs)
    ok('ended, running, interrupted',
       (jobs['1']['state'], jobs['2']['state'], jobs['3']['state']),
       ('ok', 'running', 'interrupted'))
    ok('...the last line of one that has not ended, all its lines',
       (jobs['2'].get('lines'), bool(jobs['2'].get('last_at'))), (2, True))
    ok('the checks', [c['check_id'] for c in store.acme_checks_view(1)['checks']], ['7'])

    print('\nacme: letting old lines go')
    isemon.CONFIG['retain_acmelog_days'] = 30
    store.TIDY_STRIDE = 1
    store.tidy_acme()
    ok('older than kept: gone, a stride at a time',
       store.db.execute("SELECT COUNT(*) FROM acme_events WHERE cert = 'old'").fetchone()[0], 0)
    ok('...and the certificate with them', 'old' in {c['cert'] for c in store.acme_certificates()},
       False)
    isemon.CONFIG['retain_acmelog_days'] = 400

    print('\nWhat a stopped daemon left')
    bdir = Path(isemon.BACKUP_DIR)
    bdir.mkdir(exist_ok=True)
    old = time.time() - 7 * 3600
    half = bdir / 'isemon-20260101.db.part'
    half.write_bytes(b'x')
    os.utime(str(half), (old, old))
    fresh = bdir / 'isemon-20260102.db.part'
    fresh.write_bytes(b'x')
    going = bdir / 'isemon-restore-a'
    going.mkdir()
    (going / 'big.db').write_bytes(b'x')
    os.utime(str(going), (old, old))
    left = bdir / 'isemon-restore-b'
    left.mkdir()
    (left / 'big.db').write_bytes(b'x')
    os.utime(str(left / 'big.db'), (old, old))
    os.utime(str(left), (old, old))
    isemon._HALVES_AT[0] = 0
    isemon.rb_tidy_folders()
    ok('a half older than six hours gone, a fresh one kept',
       (half.exists(), fresh.exists()), (False, True))
    ok('a restore\'s folder still being written kept, one left behind gone',
       (going.exists(), left.exists()), (True, False))
    ok('the work folders of an upgrade among those tidied',
       ('isemon-online-' in isemon.RB_WORK_PREFIXES, 'isemon-package-' in isemon.RB_WORK_PREFIXES),
       (True, True))

    print('\nThe debug switch left on')
    isemon.CONFIG['debug'] = 1
    was = isemon.LOG_DEBUG_MOST
    isemon.LOG_DEBUG_MOST = 2000
    isemon.open_log(state / 'debug.log')
    isemon._LOG_BIG.update(n=0, said=False, big=False)
    for i in range(1500):
        isemon.log('debug line %d %s' % (i, 'x' * 40), 'debug')
    isemon.log('a warning still written', 'warn')
    text = Path(isemon._LOG_FILE.name).read_text()
    ok('past the size: debug lines held back, and said once',
       (len(text) < 40000, text.count('debug lines are held back'),
        'a warning still written' in text), (True, 1, True))
    isemon.LOG_DEBUG_MOST = was
    isemon.CONFIG['debug'] = 0
finally:
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
