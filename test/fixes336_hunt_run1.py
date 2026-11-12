#!/usr/bin/env python3
"""1.10.336: bug hunt, run 1 - settings: a save breaking a second rule beside
one broken before; acme's full sync: two acme installations, an HA pair's
other node, another host's certificates, an older sync read again, a failure
the sync knew was put right, keys too long for MariaDB, deployments holding
an old certificate.

    ./test/fixes336_hunt_run1.py
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


print('Settings')
was = {'banfeed': 1, 'banfeed_auth': 'basic', 'banfeed_user': ''}
try:
    isemon.check_settings_saved(dict(was, block_lots=3, block_tries=5), was)
    got = 'accepted'
except ValueError as e:
    got = str(e)[:40]
ok('a save breaking a new rule beside one broken before: refused for the new one', got,
   'a burst that goes out for good (3) has t')
ok('...one changing nothing about the broken rule still goes through',
   bool(isemon.check_settings_saved(dict(was, block_minutes=90), was)))
ok('the two name rules say which', [m.split('(')[-1] for m in isemon.settings_problems(
    {'geolist_name': 'x', 'mikrotik_list': 'x', 'pf_geolist': 'y', 'pf_list': 'y'})],
   ['MikroTik)', 'pfSense)'])

NOW = time.time()


def stamp(off=0):
    return time.strftime('%b %e %H:%M:%S', time.localtime(NOW + off))


def jl(host, body, off=-60):
    return '%s %s acme-jobs[1]: level=info %s' % (stamp(off), host, body)


def sync(host, sid, certs, deploys=(), off=-60, fp='AA'):
    out = [jl(host, 'kind=sync node=%s event=begin sync=%s certificates=%d deployments=%d checks=0 '
                    'targets=0 sources=0 msg="b"' % (host, sid, len(certs), len(deploys)), off)]
    for cid, name, state in certs:
        out.append(jl(host, 'kind=sync node=%s event=object object=certificate cert=%s cert_id=%s '
                            'cert_state=%s fingerprint=%s not_after=2099-01-01T00:00:00Z sync=%s msg="c"'
                      % (host, name, cid, state, fp, sid), off))
    for did, cid, name, target, state, dfp in deploys:
        out.append(jl(host, 'kind=sync node=%s event=object object=deployment cert=%s cert_id=%s '
                            'deploy_id=%s target=%s deploy_state=%s deployed_fp=%s sync=%s msg="d"'
                      % (host, name, cid, did, target, state, dfp, sid), off))
    out.append(jl(host, 'kind=sync node=%s event=end sync=%s msg="e"' % (host, sid), off))
    return out


work = Path(tempfile.mkdtemp(prefix='isemon-336-'))
try:
    isemon.DB_FILE = work / 'd.db'
    (work / 'config.json').write_text(json.dumps({'db_engine': 'sqlite'}))
    isemon.CONFIG_FILE = work / 'config.json'

    def fresh():
        (work / 'd.db').unlink(missing_ok=True)
        return isemon.Storage(isemon.DB_FILE)

    def feed(st, lines):
        for rec in isemon.acme_parse_lines(lines):
            if rec.tag == 'acme-jobs' and (rec.fields or {}).get('kind') == 'sync':
                st.acme_sync_note(rec)
            else:
                st.acme_note(rec)

    def states(st):
        return {c['cert']: (c['state'], sorted(t['target'] for t in c['targets']))
                for c in st.acme_view(30)['certs']}

    print('\nTwo acme installations')
    st = fresh()
    feed(st, sync('acmeA', 'a1', [('1', 'a.example.com', 'ok')], [('1', '1', 'a.example.com', 'tA', 'ok', 'AA')]))
    feed(st, sync('acmeB', 'b1', [('1', 'b.example.com', 'ok')], [('1', '1', 'b.example.com', 'tB', 'failed', 'AA')]))
    ok('each keeps its own deployments, by host and id',
       states(st), {'a.example.com': ('ok', ['tA']), 'b.example.com': ('deploy_failed', ['tB'])})

    print('\nAn HA pair: the next sync sent from the other node')
    st = fresh()
    feed(st, sync('acme1', 's1', [('1', 'x.example.com', 'ok'), ('2', 'y.example.com', 'ok')], off=-120))
    feed(st, sync('acme2', 's2', [('2', 'y.example.com', 'ok')], off=-60))
    ok('what the first node said and the cluster no longer has: gone', states(st),
       {'x.example.com': ('deleted', []), 'y.example.com': ('ok', [])} if
       'x.example.com' in states(st) else {'y.example.com': ('ok', [])})
    ok('...not "ok" for ever', states(st).get('x.example.com', ('gone',))[0] != 'ok')

    print('\nAnother host\'s certificates')
    st = fresh()
    feed(st, ['%s acmeB acme-certs[1]: level=info kind=cert action=issued cert=b-live.example.com '
              'msg="issued"' % stamp(-300)])
    feed(st, sync('acmeA', 'a1', [('1', 'a.example.com', 'ok')]))
    ok('a whole sync of one acme does not delete what another said', states(st)['b-live.example.com'][0], 'ok')

    print('\nAn older sync read again')
    st = fresh()
    feed(st, sync('acme1', 'snew', [('1', 'x.example.com', 'ok'), ('2', 'new.example.com', 'ok')], off=-60))
    feed(st, sync('acme1', 'sold', [('1', 'x.example.com', 'failed')], off=-3600))
    ok('what the newer one said stands', (states(st)['x.example.com'][0], states(st)['new.example.com'][0],
                                           st.acme_sync_said()['sync']), ('ok', 'ok', 'snew'))

    print('\nA failure the sync knew was put right')
    st = fresh()
    feed(st, ['%s acme1 acme-certs[1]: level=bad kind=cert action=renew result=failed cert=x.example.com '
              'msg="renewal failed"' % stamp(-3000)])
    feed(st, sync('acme1', 's1', [('1', 'x.example.com', 'ok')], off=-600))
    feed(st, ['%s acme1 acme-certs[1]: level=info kind=cert action=deployed cert=x.example.com target=t '
              'msg="deployed"' % stamp(-30)])
    ok('a later line about something else does not bring it back', states(st)['x.example.com'][0], 'ok')

    print('\nKeys and deployments')
    st = fresh()
    long = 'n' * 400
    feed(st, sync('acme1', 's1', [('1', 'x.example.com', 'ok')],
                  [('1', '1', 'x.example.com', long, 'ok', 'OLD')]))
    row = st.db.execute("SELECT okey FROM acme_sync WHERE object = 'deployment'").fetchone()
    ok('a key fits every engine (a long one by its hash)', len(row['okey']) <= 160)
    ok('a target holding an older certificate than acme has is not "deployed"',
       states(st)['x.example.com'][0], 'deploy_failed')
finally:
    shutil.rmtree(str(work), ignore_errors=True)

print('\nThe domain\'s own lines (as a real controller writes them, names made up)')
H = 'Nov 10 06:00:00 dc2 WinSecurity: EventID=%d | %s'
L4625 = ('An account failed to log on.  Subject:  Security ID:  S-1-5-18  Account Name:  DC2$  Account '
         'Domain:  CORP  Logon ID:  0x3E7  Logon Type:   3  Account For Which Logon Failed:  Security ID:  '
         'S-1-0-0  Account Name:  %s  Account Domain:  CORP  Failure Information:  Failure Reason:  '
         '%%%%2304  Status:  %s  Sub Status:  %s  Process Information:  Caller Process ID:  0x2a4  Caller '
         'Process Name:  C:\\Windows\\System32\\lsass.exe  Network Information:  Workstation Name: DC2  '
         'Source Network Address: 10.0.0.9  Source Port:  0')
f = isemon.win_record_from(H % (4625, L4625 % ('ok_user', '0xC00002EE', '0x0'))).facts
ok('a 4625 with Sub Status 0x0 is not "it worked": its Status says why',
   f['said'], 'the sign-in was broken off before it finished')
f = isemon.win_record_from(H % (4625, L4625 % ('', '0xC000006D', '0xC0000064'))).facts
ok('...and with no name in its account section: no account - not the controller\'s own',
   (f['account'], f['is_machine']), ('', 0))
f = isemon.win_record_from(H % (4662, 'An operation was performed on an object.  Subject :  Security ID:  '
                                      'S-1-5-21-1  Account Name:  svc_x  Account Domain:  CORP  Logon ID:  '
                                      '0x1  Object:  Object Server:  DS')).facts
ok('a section written "Subject :" is still the subject: who did it is kept', f['by'], 'svc_x')
f = isemon.win_record_from(H % (4648, 'A logon was attempted using explicit credentials.  Subject:  '
                                      'Security ID:  S-1-5-18  Account Name:  DC2$  Account Whose '
                                      'Credentials Were Used:  Account Name:  u1  Target Server:  Target '
                                      'Server Name:  localhost  Network Information:  Network Address: '
                                      '10.0.0.5  Port:  1')).facts
ok('a 4648 to localhost names no machine', (f['account'], f['machine'], f['ip']), ('u1', '', '10.0.0.5'))
ok('the dead-account card is about accounts, not tickets that ran out',
   'expired' not in isemon.Storage.DEAD_WORDS and 'account has expired' in isemon.Storage.DEAD_WORDS)
src = (ROOT / 'isemon.py').read_text()
ok('the spray card leaves the controllers out, and reading again keeps the other logs\' why',
   ("by == 'machine' and win_short_name(r['said']) in WIN_CONTROLLERS" in src,
    "if not reason and event in WIN_AD25_FILL:" in src), (True, True))

print('\nThe Domain page')
page = (ROOT / 'web' / 'index.php').read_text()
ok('an alarm of Before Windows Server 2025 opens that page at the window it was counted over',
   "var hours = TAB === 'overview' && typeof overHours === 'function' ? overHours() : winHours();" in page)
ok('the Overview\'s popups count machine accounts as the Overview did, whatever the events page ticked',
   ": !!(WIN && WIN.machines_shown)));" in page)
ok('a row opens the events at the 2025 page\'s own window, not a month',
   "var w = $('w-hours'), best = null;" in page)
ok('"Everything" counts every kind', 'var every = WCOUNTS || {};' in page)
ok('F5 keeps the 2025 page\'s own page', ("return 'ad2025' + (typeof A25 !== 'undefined' && A25.page" in page,
                                           'window.A25_WANT = want' in page), (True, True))
ok('the words the daemon hands the Domain page are among those put into Czech',
   all(w in page for w in ('Refusals and lockouts', 'LDAP simple bind in the clear',
                           'An account asked to replicate the directory')))

print('\n%d passed, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
