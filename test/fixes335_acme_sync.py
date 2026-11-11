#!/usr/bin/env python3
"""1.10.335: acme's first full sync (acme 1.0.71) - kind=sync lines of
acme-jobs: the objects kept, a whole sync replacing what the host said
before, history and jobs kept once and never beside the live lines, the
page filled from it.

    ./test/fixes335_acme_sync.py
"""
import json
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


NOW = time.time()
STAMP = time.strftime('%b %e %H:%M:%S', time.localtime(NOW - 60))
FUTURE = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(NOW + 380 * 86400))
PAST = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(NOW - 10 * 86400))
PAST_S = time.strftime('%b %e %H:%M:%S', time.localtime(NOW - 10 * 86400))


def jl(body, stamp=STAMP, tag='acme-jobs'):
    return '%s acme %s[1007]: level=info %s' % (stamp, tag, body)


def sync(sid, certs, deploys, checks, extra=(), end=True, counts=None, days=0):
    c = counts or {'certificates': len(certs), 'deployments': len(deploys), 'checks': len(checks),
                   'targets': 1, 'sources': 1}
    out = [jl('kind=sync node=acme1 who=admin certificates=%(certificates)d checks=%(checks)d '
              'days=%(days)d deployments=%(deployments)d event=begin sources=%(sources)d '
              'sync=%(sid)s targets=%(targets)d msg="the first full sync of acme begins"'
              % dict(c, sid=sid, days=days)),
           jl('kind=sync node=acme1 who=admin event=object object=source name=LetsEncrypt '
              'module_kind=acme enabled=1 sync=%s msg="source LetsEncrypt"' % sid),
           jl('kind=sync node=acme1 who=admin event=object object=target name=web01-nginx '
              'module_kind=local enabled=1 last_ok=%s sync=%s msg="target web01-nginx"' % (PAST, sid))]
    for cid, name, state in certs:
        out.append(jl('kind=sync node=acme1 who=admin auto_renew=1 cert=%s cert_id=%s cert_state=%s '
                      'cn=%s days_left=380 enabled=1 event=object fails=0 fingerprint=AA issuer="Interni '
                      'CA" key_type=ec-256 last_ok=%s names="%s,www.%s" not_after=%s '
                      'object=certificate serial=762B owner=it source=issuer sync=%s version=2 '
                      'msg="certificate %s"' % (name, cid, state, name, PAST, name, name, FUTURE, sid,
                                                name)))
    for did, cid, name, state in deploys:
        out.append(jl('kind=sync node=acme1 who=admin cert=%s cert_id=%s deploy_id=%s target=web01-nginx '
                      'deploy_state=%s enabled=1 deployed_version=2 deployed_fp=AA event=object '
                      'object=deployment sync=%s msg="deployment %s on web01-nginx"'
                      % (name, cid, did, state, sid, name)))
    for kid, cid, name in checks:
        out.append(jl('kind=sync node=acme1 who=admin cert=%s cert_id=%s check_id=%s test=web state=unreachable '
                      'after=- event=object object=check sync=%s msg="127.0.0.1:8443 cannot be reached"'
                      % (name, cid, kid, sid)))
    out += list(extra)
    if end:
        out.append(jl('kind=sync node=acme1 who=admin event=end sync=%s lines=%d events=0 jobs=0 took_ms=31 '
                      'msg="the first full sync of acme is done"' % (sid, len(out) + 1)))
    return out


work = Path(tempfile.mkdtemp(prefix='isemon-335-'))
try:
    isemon.DB_FILE = work / 'd.db'
    (work / 'config.json').write_text(json.dumps({'db_engine': 'sqlite'}))
    isemon.CONFIG_FILE = work / 'config.json'
    st = isemon.Storage(isemon.DB_FILE)

    def feed(lines):
        for rec in isemon.acme_parse_lines(lines):
            if rec.tag == 'acme-jobs' and (rec.fields or {}).get('kind') == 'sync':
                st.acme_sync_note(rec)
            elif rec.tag == 'acme-jobs':
                st.acme_job_note(rec)
            else:
                st.acme_note(rec)

    print('Before any sync')
    ok('the page as it always was: no certificates', (st.acme_view(30)['kpi']['certs'],
                                                      st.acme_view(30)['sync']), (0, None))

    print('\nA whole sync')
    live_hist = jl('kind=cert action=issued cert=intranet.example.com msg="issued intranet.example.com v2"',
                   stamp=PAST_S, tag='acme-certs')
    feed([live_hist])
    hist_at = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(
        isemon.acme_parse_lines([live_hist])[0].ts))
    extra = [
        jl('kind=sync node=acme1 event=history at=%s event_node=acme1 by=admin sync=s1 '
           'msg="issued intranet.example.com v2"' % hist_at, stamp=PAST_S),
        jl('kind=sync node=acme1 event=history at=%s event_node=acme1 by=admin sync=s1 '
           'msg="renewed old.example.com"' % PAST, stamp=PAST_S),
        jl('kind=sync node=acme1 event=job job=77 job_kind=renew cert=intranet.example.com cert_id=1 '
           'at=%s finished=%s state=ok ok=1 took_ms=102 by=admin job_node=acme1 steps=2 version=2 '
           'sync=s1 msg="version 2, valid until later"' % (PAST, PAST), stamp=PAST_S),
        jl('kind=sync node=acme1 event=job_step job=77 job_kind=renew cert=intranet.example.com cert_id=1 '
           'seq=1 at=%s sync=s1 msg="issuing intranet.example.com"' % PAST, stamp=PAST_S),
        jl('kind=sync node=acme1 event=job_step job=77 job_kind=renew cert=intranet.example.com cert_id=1 '
           'seq=2 at=%s sync=s1 msg="done"' % PAST, stamp=PAST_S),
    ]
    feed(sync('s1', [('1', 'intranet.example.com', 'ok'), ('2', 'mail.example.com', 'failed')],
              [('1', '1', 'intranet.example.com', 'ok'), ('2', '2', 'mail.example.com', 'failed')],
              [('1', '1', 'intranet.example.com')], extra))
    v = st.acme_view(30)
    by = {c['cert']: c for c in v['certs']}
    ok('every certificate it holds, with its state', (v['kpi']['certs'], by['intranet.example.com']['state'],
                                                      by['mail.example.com']['state']),
       (2, 'ok', 'failing'))
    ok('...its names, its end, its targets from the deployments',
       (by['intranet.example.com']['names'], bool(by['intranet.example.com']['not_after']),
        [t['target'] for t in by['intranet.example.com']['targets']]),
       ('intranet.example.com,www.intranet.example.com', True, ['web01-nginx']))
    ok('...and what acme says of it besides, and its checks',
       (by['intranet.example.com']['acme']['owner'], by['intranet.example.com']['acme']['key_type'],
        [c['check_id'] for c in by['intranet.example.com']['checks']]), ('it', 'ec-256', ['1']))
    ok('the targets acme has, its modules, the sync for the header',
       (v['kpi']['targets'], sorted(m['object'] for m in v['modules']), v['sync']['sync'],
        v['sync']['whole']), (1, ['source', 'target'], 's1', True))
    hist = [r['msg'] for r in st.db.execute("SELECT msg FROM acme_events ORDER BY ts")]
    ok('history: kept by its own time, the one the live line already said not twice',
       hist, ['issued intranet.example.com v2', 'renewed old.example.com'])
    jobs = st.acme_jobs_list(NOW - 30 * 86400)
    ok('a past job: begun and ended, as a job of the jobs page',
       [(j['job'], j['state'], j['took_ms']) for j in jobs], [('77', 'ok', 102)])
    ok('...with its steps', [r['msg'] for r in st.acme_job_lines('77', 'acme1') if r.get('event') == 'step'],
       ['issuing intranet.example.com', 'done'])
    chk = st.acme_checks_view(30)['checks']
    ok('the checks page: the check as acme had it', [(c['check_id'], c['state']) for c in chk],
       [('1', 'unreachable')])

    print('\nThe same sync again')
    n_ev, n_jobs = st.rows_in('acme_events'), st.rows_in('acme_jobs')
    feed(sync('s2', [('1', 'intranet.example.com', 'ok'), ('2', 'mail.example.com', 'failed')],
              [('1', '1', 'intranet.example.com', 'ok'), ('2', '2', 'mail.example.com', 'failed')],
              [('1', '1', 'intranet.example.com')],
              [x.replace('sync=s1', 'sync=s2') for x in extra]))
    ok('history and jobs not kept twice', (st.rows_in('acme_events'), st.rows_in('acme_jobs')),
       (n_ev, n_jobs))

    print('\nA later live line wins')
    feed([jl('kind=cert action=renew result=failed cert=intranet.example.com msg="renewal failed"',
             stamp=time.strftime('%b %e %H:%M:%S', time.localtime(NOW + 5)), tag='acme-certs')])
    by = {c['cert']: c for c in st.acme_view(30)['certs']}
    ok('...over the sync for that certificate', by['intranet.example.com']['state'], 'failing')

    print('\nA certificate gone from acme')
    feed(sync('s3', [('2', 'mail.example.com', 'ok')], [('2', '2', 'mail.example.com', 'ok')], []))
    by = {c['cert']: c for c in st.acme_view(30)['certs']}
    ok('a whole sync no longer naming one: gone, unless a live line spoke of it since',
       (by['mail.example.com']['state'], by['intranet.example.com']['state']), ('ok', 'failing'))
    ok('...its check gone with it', st.acme_checks_view(30)['checks'], [])

    print('\nA sync that did not end')
    feed(sync('s4', [('9', 'new.example.com', 'ok')], [], [], end=False))
    by = {c['cert']: c for c in st.acme_view(30)['certs']}
    ok('its objects kept, nothing let go', ('new.example.com' in by, by['mail.example.com']['state']),
       (True, 'ok'))
    feed(sync('s5', [('9', 'new.example.com', 'ok')], [], [], counts={
        'certificates': 3, 'deployments': 0, 'checks': 0, 'targets': 1, 'sources': 1}))
    by = {c['cert']: c for c in st.acme_view(30)['certs']}
    ok('...nor one that ended with fewer than it began with', (by['mail.example.com']['state'],
                                                               st.acme_sync_said()['whole']),
       ('ok', False))
finally:
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d passed, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
