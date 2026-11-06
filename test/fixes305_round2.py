#!/usr/bin/env python3
"""1.10.305: what the second round of looking for bugs found, fixed.

    ./test/fixes305_round2.py
"""
import json
import shutil
import sys
import tempfile
import time
import types
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


src = (ROOT / 'isemon.py').read_text()
web = (ROOT / 'deploy' / 'isemon_web.py').read_text()
inst = (ROOT / 'install.sh').read_text()
work = Path(tempfile.mkdtemp(prefix='isemon-305-'))
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
    isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0})
    (state / 'config.json').write_text(json.dumps({'db_engine': 'sqlite'}))
    store = isemon.Storage(isemon.DB_FILE)
    daemon = isemon.Daemon(store)

    print('Threads, the clock, the programs run')
    ok('stopping cannot wait on a lock its own thread holds',
       isinstance(isemon.RosReaders(daemon).lock, type(isemon.threading.RLock())))
    ok('a clock that went back: everything on a schedule done at once',
       'the clock went back %s: everything that runs on a schedule here is' in src)
    t0 = time.time()
    try:
        out = work / 'out'
        with open(out, 'wb') as f:
            isemon.run_program(['sleep', '30'], into=f, seconds=1, words='sleep')
        ok('a program pumped into a file is stopped at its time', False)
    except isemon.StorageError as e:
        ok('a program pumped into a file is stopped at its time',
           ('was still going' in str(e), time.time() - t0 < 10), (True, True))
    real = isemon.threading.Thread.start

    def broken(self):
        raise RuntimeError("can't start new thread")
    isemon.threading.Thread.start = broken
    try:
        daemon.job_start('rescan', lambda progress: {}, by='test')
    except RuntimeError:
        pass
    finally:
        isemon.threading.Thread.start = real
    stuck = [j for j in daemon._jobs.values() if j['kind'] == 'rescan'] if \
        hasattr(daemon, '_jobs') else []
    ok('a job whose thread would not start is not left running for good',
       [j['done'] for j in stuck], [True] * len(stuck))

    print('\nRoot')
    ok('a change of the network, the clock or a restart asked too long ago: not done',
       ('def ask_stale(r):' in web, web.count('if what != \'read\' and ask_stale(r):'),
        "wr.write(NET_ASK_NAME, dict(data, id=ask_id, at=time.time()))" in src,
        "wr.write('ntp.ask', dict(data, id=ask_id, at=time.time()))" in src), (True, 2, True, True))
    ok('...and the daemon takes back the one it gave up on',
       "os.unlink(str(wr.folder() / NET_ASK_NAME))" in src)
    ok('the network profile put back when what comes after it fails',
       "net_run(back, 'nmcli connection modify (back)')" in web)
    ok('no restart, no change of the network in the middle of an upgrade - nor one under them',
       (src.count("raise WebRootError('isemon is being upgraded - wait for it to end')"),
        "if np_.power_busy():" in src), (2, True))
    ok('what root would not put in is asked again every six hours',
       "time.time() - float(st.get('at') or 0) < 6 * 3600:" in src)

    print('\nThe views')
    ok('a card of the Domain tab opens a list from the hour it counts from',
       "store.roll_floor(time.time() - number('hours', 0, 0, 8760) * 3600)" in src)
    ok('...and of the Traffic tab from where its sums begin',
       'since = int(since // span) * span' in src)
    ok('an acme job with no node can be opened',
       "AND COALESCE(node, '') = ? " in src)
    ok('the end of a stretch is not in it, on acme\'s lines too', "('until', '<')" in src)

    print('\nThe command line')
    isemon.CONFIG['mikrotik_password'] = isemon.seal_secret('the-real-one')
    pal = types.SimpleNamespace(bad=print, note=lambda *a: None, good=lambda *a: None,
                                kv=lambda *a: None)
    isemon.set_settings_directly({'mikrotik_password': '••••••ne'},
                                 pal, store)
    ok('a secret given back as it is shown is not saved over the real one',
       isemon.unseal_secret(isemon.CONFIG['mikrotik_password']), 'the-real-one')
    isemon.set_settings_directly({'fwlog_sources': json.dumps([
        {'name': 'mt1', 'type': 'routeros', 'path': str(work), 'api': {
            'on': 1, 'host': '10.0.0.9', 'password': 'PlainPw123', 'auth': 'password',
            'mode': 'plain'}}])}, pal, store)
    kept = json.dumps(store.settings_saved())
    ok('a firewall\'s API password set on the command line is sealed', 'PlainPw123' in kept,
       False)
    ok('root\'s own session is not held at the gates of a person\'s',
       "cli = me.get('ip') == 'command line'" in src)
    ok('the passkeys of the database that will not open are not reset',
       'cmd_del_user, cmd_switch_user, cmd_passkey_reset)' in src)
    ok('install.sh --upgrade --log-from narrows the port',
       ('LOG_FROM="$2"; SYSLOG_ASKED="yes"' in inst,
        '[[ -f "$RSYSLOG_FILE" ]]' in inst), (True, True))

    print('\nWhat the review of round one found')
    isemon.CONFIG['ios_acl_tail'] = '! keep the management\nremark ours\npermit ip any any\nend'
    store.block('198.51.100.9', None, 'for good', auto=False, by='test')
    acl = daemon.ios_acl()['text'].split('\n')
    ok('the Cisco list: a comment not numbered, an end left out',
       (' ! keep the management' in acl, any(l.strip().endswith(' end') or l.strip() == 'end'
                                          for l in acl)), (True, False))
    isemon.CONFIG['ios_acl_tail'] = isemon.DEFAULTS['ios_acl_tail']
    ok('the sources on the refusals\' table judged by the newest of their own kind',
       "SELECT MAX(ts) AS t FROM failed WHERE %s AND ts <= ?" in src)
    ok('one\'s own passkey taken away without Face ID where Face ID cannot be had',
       'checkable = daemon.passkeys_on() and any(' in src)
finally:
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
