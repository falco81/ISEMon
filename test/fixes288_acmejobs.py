#!/usr/bin/env python3
"""1.10.288: acme's jobs step by step (acme-jobs, acme 1.0.44's isemon_detail),
and a tile of acme's own in the firewall.

- A third log of acme's, acme-jobs.log: every job's start, steps, requests
  (CA, DNS API, target), validations and end, and every run of a check -
  kept once a line in acme_jobs (`before` as `prior`, the request's host as
  `http_host`), "[hidden]" kept as it came.
- The acme tab's Jobs page (/api/acmelog/jobs): how the jobs went, how long
  a renewal takes by source, the validations by provider, the requests by
  server (failures, 429, latency), who began them and the wait; a job with
  no end an hour after its last line is interrupted. One job's lines in the
  order it ran (/api/acmelog/job). The Checks page (/api/acmelog/checks):
  every check as it stands, run by run, and when one began or stopped
  failing.
- Settings → Firewall and access → What isemon lets in by itself: "acme -
  the certificate manager", with acme's TLS port and the plain syslog port
  its nodes send to, from anywhere or only from acme's nodes.

    ./test/fixes288_acmejobs.py
"""
import json
import os
import random
import shutil
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
os.environ['ISEMON_WEB_HELPER'] = '1'
import isemon                                        # noqa: E402

PASS = FAIL = 0
PORT = 19600 + random.randint(0, 90)


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


C = ('cert=www cert_id=12 cert_state=renewing challenge=dns-cz fingerprint=3FA1229C... '
     'issuer=LetsEncrypt issuer_kind=acme job=4711 job_kind=renew key_type=ec-256 '
     'names="www.example.cz,example.cz" not_after=2026-11-08T10:26:48Z '
     'not_before=2026-08-10T10:26:48Z owner=web-team')
H = '<29>Nov  4 22:10:%02d acme acme-jobs[812]: '
SPEC = [
    H % 1 + 'level=info kind=job node=acme1 who=acme %s event=start queued_ms=12 '
    'serial=04A19C552E0B7F21AB t_ms=0 version=6 msg="it ends in 29 days"' % C,
    H % 3 + 'level=info kind=job node=acme1 who=acme %s event=step module=dns-cz '
    'module_kind=challenge seq=2 serial=04A19C552E0B7F21AB t_ms=4 version=6 '
    'msg="www.example.cz is proved by dns-cz"' % C,
    H % 4 + 'level=debug kind=job node=acme1 who=acme bytes=512 %s event=http '
    'host=acme-v02.api.letsencrypt.org method=POST module=LetsEncrypt module_kind=issuer ms=184 '
    'path=/acme/new-order serial=04A19C552E0B7F21AB status=201 t_ms=210 version=6 '
    'msg="POST acme-v02.api.letsencrypt.org/acme/new-order -> 201"' % C,
    H % 6 + 'level=warn kind=job node=acme1 who=acme bytes=60 %s event=http '
    'host=api.active24.com method=PUT module=dns-cz module_kind=challenge ms=95 '
    'path=/v2/service/123/dns/record query_keys=apikey serial=04A19C552E0B7F21AB status=429 '
    't_ms=650 version=6 msg="PUT api.active24.com/v2/service/123/dns/record -> 429"' % C,
    H % 5 + 'level=info kind=job node=acme1 who=acme %s event=step module=dns-cz '
    'module_kind=challenge seq=5 serial=04A19C552E0B7F21AB t_ms=420 version=6 '
    'msg="_acme-challenge.www.example.cz TXT "[hidden]" put in (Active24)"' % C,
    H % 8 + 'level=ok kind=job node=acme1 who=acme %s challenge_type=dns-01 event=validation '
    'module=LetsEncrypt module_kind=issuer ms=20190 name=www.example.cz persist=0 '
    'serial=04A19C552E0B7F21AB state=valid t_ms=21400 version=6 via=challenge:dns-cz '
    'msg="www.example.cz: proved by dns-01"' % C,
    H % 9 + 'level=bad kind=job node=acme1 who=acme %s challenge_type=dns-01 '
    'error="the CA did not accept example.cz: urn:ietf:params:acme:error:dns - NXDOMAIN" '
    'event=validation module=LetsEncrypt module_kind=issuer ms=180000 name=example.cz '
    'persist=0 serial=04A19C552E0B7F21AB state=invalid t_ms=200400 version=6 '
    'via=challenge:dns-cz msg="example.cz: not proved"' % C,
    H % 10 + 'level=ok kind=job node=acme1 who=acme cert=www cert_id=12 cert_state=ok '
    'challenge=dns-cz event=end fingerprint=9B07E4C1... issuer=LetsEncrypt issuer_kind=acme '
    'job=4711 job_kind=renew key_type=ec-256 names="www.example.cz,example.cz" '
    'not_after=2027-02-02T21:10:00Z not_before=2026-11-04T21:10:00Z ok=1 owner=web-team '
    'result_version=7 serial=0A77F3E1C2D4B5A6 state=ok steps=31 t_ms=24050 took_ms=24050 '
    'version=7 msg="version 7, valid until 2027-02-02; 2 deployment(s) done"',
    H % 12 + 'level=bad kind=check node=acme1 who=acme before=ok cert=www cert_id=12 '
    'check_id=9 d_version=6 endpoint="HTTPS www.example.cz:443" event=result fails=1 ms=143 '
    'names="www.example.cz,example.cz" ok=0 state=old test=web-https test_kind=https went=bad '
    'msg="serves version 6 (main) of www - not the one expected"',
]
NOW = time.mktime((2026, 11, 4, 23, 0, 0, 0, 0, -1))

work = Path(tempfile.mkdtemp(prefix='isemon-288-'))
api = None
try:
    print('A line of acme-jobs, read')
    got = list(isemon.acme_parse_lines(SPEC, now=NOW))
    ok('every example of the specification', [g.tag for g in got], ['acme-jobs'] * 9)
    ok('quotes inside msg left as they came, [hidden] with them', got[4].msg,
       '_acme-challenge.www.example.cz TXT "[hidden]" put in (Active24)')
    ok('the error of a refused validation, quoted', got[6].fields['error'],
       'the CA did not accept example.cz: urn:ietf:params:acme:error:dns - NXDOMAIN')
    ok('levels ok and debug known', ('ok' in isemon.ACME_LEVELS, 'debug' in isemon.ACME_LEVELS),
       (True, True))

    state = work / 'state'
    state.mkdir()
    for k, v in dict(STATE_DIR=state, DB_FILE=state / 'd.db', BACKUP_DIR=state / 'b',
                     DUMP_DIR=state / 'dumps', RUN_DIR=state, LOG_DIR=state,
                     CONFIG_FILE=state / 'config.json', _LOG_PATH=state / 'd.log',
                     TOKEN_FILE=state / 'token').items():
        setattr(isemon, k, v)
    isemon.CONFIG.clear()
    isemon.CONFIG.update(isemon.DEFAULTS)
    logs = work / 'remote' / 'acme'
    logs.mkdir(parents=True)
    isemon.CONFIG.update({'api_port': PORT, 'geo': 0, 'mikrotik1': 0, 'acmelog': 1,
                          'acmelog_paths': [str(logs)]})
    (state / 'config.json').write_text(json.dumps({'db_engine': 'sqlite'}))
    store = isemon.Storage(isemon.DB_FILE)
    daemon = isemon.Daemon(store)
    daemon.add_user('look', 'a-third-long-password', 'readonly', by='test')

    print('\nThe settings and the files')
    D = isemon.DEFAULTS
    ok('new: read the jobs, as acme sends them by default; 90 days of them',
       (D['acmelog_jobs'], D['acmelog_jobs_name'], D['retain_acmelog_jobs_days']),
       (1, 'acme-jobs.log', 90))
    ok('the third file read', [x[1] for x in daemon.log_files() if x[0] == 'acmelog'],
       [str(logs / n) for n in ('acme-certs.log', 'acme.log', 'acme-jobs.log')])
    isemon.CONFIG['acmelog_jobs'] = 0
    ok('...not with it off', len([x for x in daemon.log_files() if x[0] == 'acmelog']), 2)
    isemon.CONFIG['acmelog_jobs'] = 1

    print('\nKept, once')
    daemon.read_records(SPEC, kind='acmelog')
    daemon.read_records(SPEC, kind='acmelog')
    n = store.db.execute('SELECT COUNT(*) AS n FROM acme_jobs').fetchone()['n']
    ok('read twice, kept once - in a table of their own', (n, store.db.execute(
        'SELECT COUNT(*) AS n FROM acme_events').fetchone()['n']), (9, 0))
    h = dict(store.db.execute("SELECT * FROM acme_jobs WHERE status = 429").fetchone())
    ok('a request: its server, status, time, module',
       (h['http_host'], h['status'], h['ms'], h['module'], h['method'], h['event']),
       ('api.active24.com', 429, 95, 'dns-cz', 'PUT', 'http'))
    ok('...the names of its query, never values, kept beside', json.loads(h['extra']).get(
        'query_keys'), 'apikey')
    ck = dict(store.db.execute("SELECT * FROM acme_jobs WHERE kind = 'check'").fetchone())
    ok('a check: before kept as prior, what it found kept beside',
       (ck['prior'], ck['state'], ck['went'], json.loads(ck['extra']).get('d_version')),
       ('ok', 'old', 'bad', '6'))

    print('\nThe Jobs page')
    now = time.time()

    def J(job, ago_s, events, **f):
        out = []
        for ev, t_ms, extra in events:
            ts = now - ago_s + t_ms / 1000.0
            fields = dict(f, event=ev, job=job, t_ms=t_ms, **extra)
            head = 'level=%s kind=job node=%s who=%s' % (fields.pop('level', 'info'),
                                                         fields.pop('node', 'acme1'),
                                                         fields.pop('who', 'acme'))
            rest = ' '.join('%s=%s' % (k, fields[k]) for k in sorted(fields))
            out.append('%s acme acme-jobs[1]: %s %s msg=x' % (
                time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(ts)), head, rest))
        return out
    lines = []
    lines += J('1', 7200, [('start', 0, {'queued_ms': 10}), ('end', 4000, {'state': 'ok', 'ok': 1,
                                                                          'took_ms': 4000})],
               job_kind='renew', cert='a', issuer='LE')
    lines += J('2', 7000, [('start', 0, {'queued_ms': 30}),
                           ('end', 9000, {'state': 'failed', 'ok': 0, 'took_ms': 9000,
                                          'level': 'bad'})],
               job_kind='renew', cert='b', issuer='LE')
    lines += J('3', 6000, [('start', 0, {}), ('end', 1000, {'state': 'ok', 'ok': 1,
                                                            'took_ms': 1000})],
               job_kind='deploy', cert='a', target='f5')
    lines += J('4', 5 * 3600, [('start', 0, {}), ('step', 10, {'seq': 1})], job_kind='renew',
               cert='c', issuer='ZS')
    lines += J('5', 60, [('start', 0, {})], job_kind='renew', cert='d', issuer='ZS')
    daemon.read_records(lines, kind='acmelog')
    v = store.acme_jobs_view(30)
    k = v['kpi']
    states = {j['job']: j['state'] for j in v['jobs']}
    ok('each job as it ended - or interrupted, or still running',
       (states['1'], states['2'], states['3'], states['4'], states['5'], states['4711']),
       ('ok', 'failed', 'ok', 'interrupted', 'running', 'ok'))
    ok('the counts', (k['jobs'], k['ok'], k['failed'], k['running'], k['interrupted']),
       (6, 3, 1, 1, 1))
    ok('a renewal takes: half within, 9 of 10 within',
       (k['renew_p50'], round(k['renew_p90'])), (9000.0, 21040))
    src = {g['key']: (g['n'], g['ok'], g['failed']) for g in v['by_issuer']}
    ok('by source', (src['LE'], src['LetsEncrypt']), ((2, 1, 1), (1, 1, 0)))
    ok('by kind', {g['key']: g['n'] for g in v['by_kind']}, {'renew': 3, 'deploy': 1})
    val = v['validations'][0]
    ok('validations by provider: proved, refused, the last refusal',
       (val['via'], val['valid'], val['invalid'], val['last_error'][:22]),
       ('challenge:dns-cz', 1, 1, 'the CA did not accept '))
    apis = {a['host']: (a['n'], a['errors'], a['limited']) for a in v['apis']}
    ok('requests by server: failures and 429', (apis['api.active24.com'],
                                                apis['acme-v02.api.letsencrypt.org']),
       ((1, 1, 1), (1, 0, 0)))
    ok('who began them', {w['who']: w['n'] for w in v['who']}, {'acme': 6})
    rows = store.acme_job_lines('4711', 'acme1')
    ok('one job, in the order it ran', [r['event'] for r in rows],
       ['start', 'step', 'http', 'step', 'http', 'validation', 'validation', 'end'])
    c = store.acme_checks_view(30)
    ok('the checks: as it stands, and when it began failing',
       (c['checks'][0]['state'], c['checks'][0]['fails'], c['incidents'][0]['went']),
       ('old', 1, 'bad'))
    with store.db_write() as db:
        db.execute("UPDATE acme_jobs SET ts = ? WHERE job = '1'", (now - 100 * 86400,))
    store.tidy_acme_jobs()
    ok('older than they are kept: let go', store.acme_job_lines('1', 'acme1'), [])
    ok('erased with what acme sent', 'acme_jobs' in isemon.Storage.ERASABLE['acmelog']['tables'])
    ok('...and counted', 'acme_jobs' in store.counts())

    print('\nThe API')
    api = isemon.ApiServer(daemon, PORT)
    api.start()
    time.sleep(0.4)

    def call(path, sess=None):
        req = urllib.request.Request('http://127.0.0.1:%d%s' % (PORT, path))
        req.add_header('X-Isemon-Token', isemon.API_TOKEN)
        if sess:
            req.add_header('X-Isemon-Session', sess)
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.status, json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode() or '{}')
    req = urllib.request.Request('http://127.0.0.1:%d/api/auth/login' % PORT,
                                 data=json.dumps({'name': 'look',
                                                  'password': 'a-third-long-password'}).encode(),
                                 method='POST')
    req.add_header('X-Isemon-Token', isemon.API_TOKEN)
    req.add_header('Content-Type', 'application/json')
    look = json.loads(urllib.request.urlopen(req, timeout=30).read().decode())['token']
    st, d = call('/api/acmelog/jobs?days=30', look)
    ok('the Jobs page', (st, d['on'], d['kpi']['failed']), (200, True, 1))
    st, d = call('/api/acmelog/job?job=4711&node=acme1', look)
    ok('one job', (st, len(d['rows']), d['rows'][0]['tag']), (200, 8, 'acme-jobs'))
    st, d = call('/api/acmelog/checks?days=30', look)
    ok('the Checks page', (st, len(d['checks'])), (200, 1))
    ok('signed out: not', call('/api/acmelog/jobs')[0], 401)

    print('\nThe firewall: a tile of acme\'s own')
    wr = daemon.webroot
    look_ = {'rsyslog': [{'file': '10-ise.conf', 'proto': 'udp', 'port': '514'},
                         {'file': '10-ise.conf', 'proto': 'tcp', 'port': '514'},
                         {'file': '99-tls-acme.conf', 'proto': 'tcp', 'port': '6516'},
                         {'file': '99-otp-tls.conf', 'proto': 'tcp', 'port': '6514'}],
             'ssh': ['22']}
    items = {i['key']: i for i in wr.auto_rules(look=look_, access={'dashboard': {'any': True}})}
    a = items.get('acmetls')
    ok('there, called what it is', (a or {}).get('title'), 'acme - the certificate manager')
    ok('...its TLS port alone - the plain 514 is The logs arriving\'s (1.10.289)',
       sorted({(r['proto'], r['port']) for r in a['rules']}), [('tcp', '6516')])
    ok('...and 514 still let in there', sorted({(r['proto'], r['port']) for r in
                                                items['logs']['rules']}),
       [('tcp', '514'), ('udp', '514')])
    ok('...its TLS port no longer one of the logs arriving',
       '6516' in {r['port'] for r in items['logs']['rules']}, False)
    ok('...otp\'s as it was', sorted({r['port'] for r in items['otptls']['rules']}), ['6514'])
    fw = wr.fw_conf()
    fw['acmetls'] = {'any': False, 'from': ['192.0.2.10/32']}
    a = {i['key']: i for i in wr.auto_rules(look=look_, fw=fw,
                                            access={'dashboard': {'any': True}})}['acmetls']
    ok('only from acme\'s nodes: its port from each of them',
       sorted({(r['port'], r['source']) for r in a['rules']}), [('6516', '192.0.2.10/32')])
    ok('a tile that can be turned off', 'acmetls' in isemon.WebRoot.AUTO)
    isemon.CONFIG['acmelog'] = 0
    items = {i['key'] for i in wr.auto_rules(look={'rsyslog': look_['rsyslog'][:2]},
                                             access={'dashboard': {'any': True}})}
    ok('not there while acme is not read and has no port of its own', 'acmetls' in items, False)
    isemon.CONFIG['acmelog'] = 1
    a = {i['key']: i for i in wr.auto_rules(look={'rsyslog': look_['rsyslog'][:2]},
                                            access={'dashboard': {'any': True}})}['acmetls']
    ok('read, no TLS yet: there, letting nothing in, saying why',
       (a['rules'], 'no port of its own yet' in a['why']), ([], True))
    isemon.CONFIG['acmelog'] = 1
    try:
        wr.firewall_save({'acmetls': {'any': False, 'from': []}}, 'test')
        ok('acme\'s nodes from nobody: refused', False)
    except isemon.WebRootError as e:
        ok('acme\'s nodes from nobody: refused', 'acme\'s nodes' in str(e))

    print('\nThe page')
    page = (ROOT / 'web' / 'index.php').read_text()
    ok('the Jobs and Checks pages, and their roads',
       all(x in page for x in ("['jobs', 'Jobs', 'gear']", "['checks', 'Checks', 'check']",
                               "'acmelog-jobs'   => '/api/acmelog/jobs'",
                               "'acmelog-job'    => '/api/acmelog/job'",
                               "'acmelog-checks' => '/api/acmelog/checks'")))
    ok('the firewall tile has its senders', "item.key === 'acmetls' ? FW.draft.acmetls" in page)
    ok('[hidden] said as hidden on purpose', "'hidden on purpose'" in page)
    rule = (ROOT / 'deploy' / 'rsyslog-acme.conf').read_text()
    ok('rsyslog files acme-jobs too', '$programname == "acme-jobs"' in rule)
finally:
    if api is not None:
        try:
            api.stop()
        except Exception:
            pass
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
