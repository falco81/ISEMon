#!/usr/bin/env python3
"""1.10.238: what three more reviews found.

- Settings - Time: a host name with a line end in it refused (it put a line of
  its own into chrony.conf, which chronyd refuses); chrony.conf never rewritten
  while isemon does not set the servers; a begin mark without its end refused
  rather than everything after it taken away; capitalised directives
  commented out too; a file in Latin-2 read; numbers too big for a number
  refused; "Step it now" or "Save" asked while another tick ran not lost;
  a folder put in place of ntp.ask moved aside.
- Firewall and access: the trial running out, Keep and a save under one lock;
  who may reach which page never changed on trial where it could not be put
  back exactly; an allow of nginx's that is no address does not stop the page;
  the requests to root readable by the isemon account alone; a request root
  never finished not waited on for ever; folders in place of the asking files
  moved aside; a chain declared after INPUT's first rule not written twice.
- Backups of the configuration: this machine's settings.key stays its own -
  what the backup's key sealed is opened with it and sealed again with this
  one's; a configuration refused changes nothing; the guide of the kind made
  now; each kind kept on its own; a restore and a backup never at once; a
  password kept only for the server it was typed for; SCP's folder plain;
  IPv6 servers for scp, sftp and smbclient.
- A refusal of a request whose body nobody read reads it first: a 403, not a
  reset connection.

    ./test/fixes238.py
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
os.environ['ISEMON_WEB_HELPER'] = '1'
import isemon                                        # noqa: E402

PASS = FAIL = 0
PW = 'Backups-Password-1234'


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


def refused(what, fn, *a, kind=Exception):
    try:
        fn(*a)
        ok(what, 'taken', 'refused')
    except kind:
        ok(what, True)


WORK = Path(tempfile.mkdtemp(prefix='isemon-238-'))


def machine(name):
    state = WORK / name
    (state / 'web').mkdir(parents=True)
    for k, v in dict(STATE_DIR=state, DB_FILE=state / 'isemon.db', BACKUP_DIR=state / 'backups',
                     DUMP_DIR=state / 'dumps', RUN_DIR=state, LOG_DIR=state,
                     CONFIG_FILE=state / 'config.json', _LOG_PATH=state / 'd.log',
                     TOKEN_FILE=state / 'api-token').items():
        setattr(isemon, k, v)
    (state / 'config.json').write_text(json.dumps({'db_engine': 'sqlite'}))
    isemon.load_config(state / 'config.json')
    isemon.CONFIG.update({'geo': 0, 'site_name': 'Test site', 'mikrotik1': 0})
    isemon.Storage._unsealable = set()
    store = isemon.Storage(isemon.DB_FILE)
    isemon.apply_saved_settings(store)
    return state, store, isemon.Daemon(store)


try:
    # ------------------------------------------------------------------------
    print('Settings - Time, root\'s half')
    import importlib.util
    spec = importlib.util.spec_from_file_location('isemon_web_238',
                                                  str(ROOT / 'deploy' / 'isemon_web.py'))
    W = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(W)
    W.NTP_NO_SERVICE = True
    W.NO_SERVICES = True
    conf = WORK / 'chrony.conf'
    W.CHRONY_CONF = str(conf)
    W.CHRONYC = W.TIMEDATECTL = '/bin/true'
    refused('a host name with a line end in it', W.ntp_checked,
            {'manage': True, 'servers': [{'host': 'pool.ntp.org\n.'}]}, kind=W.Refused)
    refused('...and on the daemon\'s side', isemon.ntp_checked,
            {'manage': True, 'servers': [{'host': 'pool.ntp.org\n.'}]}, kind=isemon.WebRootError)
    refused('a number too big for one', W.ntp_checked,
            {'manage': True, 'servers': [{'host': 'a.b'}], 'makestep': [1e999, 3]},
            kind=W.Refused)
    refused('...on the daemon\'s side too', isemon.ntp_checked,
            {'manage': True, 'servers': [{'host': 'a.b'}], 'step_s': 1e999},
            kind=isemon.WebRootError)
    off = W.ntp_checked({'manage': False})
    for text in ('pool a iburst\nrtcsync\n\n', 'pool a iburst\nrtcsync', '',
                 'pool a iburst # x\x0cmore\nrtcsync\n'):
        ok('not set by isemon: the file exactly as it is (%r)' % text[:20],
           W.ntp_conf_text(text, off), text)
    half = 'pool a\n%s\nserver b\nkeyfile /etc/chrony.keys\n' % W.NTP_BEGIN
    refused('a begin mark without its end: refused, nothing taken away',
            W.ntp_conf_text, half, off, kind=W.Refused)
    on = W.ntp_checked({'manage': True, 'servers': [{'host': 'time.example.cz'}]})
    got = W.ntp_conf_text('Server 10.0.0.1 iburst\nPOOL x.example\nrtcsync\n', on)
    ok('capitalised directives commented out', ('#isemon# Server 10.0.0.1' in got,
                                                 '#isemon# POOL x.example' in got), (True, True))
    conf.write_bytes('# \xec\xe8 by hand\npool a iburst\n'.encode('latin-1'))
    ok('a chrony.conf in Latin-2 read', W.ntp_read().get('own'), ['pool a iburst'])
    W.write_root(str(conf), W.chrony_read(), 0o644)
    ok('...and written back byte for byte', conf.read_bytes()[:4], b'# \xec\xe8')
    old_cwd = os.getcwd()
    (WORK / 'rootstate' / 'web' / 'ntp.ask' / 'x').mkdir(parents=True)
    W.STATE_DIR = str(WORK / 'rootstate')
    W.FD[0] = None
    try:
        W.ntp_drop(W.web_fd())
        ok('a folder with something in it in place of ntp.ask: moved aside',
           (WORK / 'rootstate' / 'web' / 'ntp.ask').exists(), False)
    except Exception as e:                      # noqa: BLE001
        ok('a folder in place of ntp.ask (%s)' % e, False)
    os.chdir(old_cwd)
    src = (ROOT / 'deploy' / 'isemon_web.py').read_text()
    ok('chronyd checks the file before it is put in, and it is put back when chronyd will not '
       'start', ("'-p', '-f', tmp" in src, 'chrony.conf put back as it was' in src), (True, True))
    ok('a time zone that cannot be set is said, the servers set all the same',
       'the time zone was NOT set' in src)

    print('\nSettings - Time, the daemon: nothing asked is lost')
    isemon.NTP_WORK.update(busy=True, apply_now=False, want_sync=time.time(), synced=0.0)

    class WR(object):
        def helper_there(self):
            return True

        def folder(self):
            return WORK

        def _meta(self, k, d=None):
            return d
    real = isemon._ntp_thread
    isemon._ntp_thread = lambda wr, fn, *a: False      # another tick has it
    isemon.NTP_WORK['busy'] = False
    isemon.ntp_tick(WR())
    ok('a step asked while another tick ran is still asked', isemon.NTP_WORK['want_sync'] >
       isemon.NTP_WORK['synced'])
    isemon._ntp_thread = real
    isemon.NTP_WORK.update(want_sync=0.0, synced=0.0)

    # ------------------------------------------------------------------------
    print('\nFirewall and access')
    state, store, daemon = machine('fw')
    wr, np = daemon.webroot, daemon.netpower
    ok('the trial has a lock of its own', hasattr(np, 'fw_lock'))
    nginx = WORK / 'isemon.conf'
    certs = WORK / 'certs'
    certs.mkdir()
    nginx.write_text((ROOT / 'deploy' / 'nginx-isemon.conf').read_text()
                     .replace('/etc/nginx/certs', str(certs))
                     .replace('    allow 10.0.0.0/8;\n', '    allow 10.0.0.0/8;\n    allow unix:;\n'))
    env = dict(os.environ, ISEMON_STATE=str(state), ISEMON_WEB_NO_SERVICES='1',
               ISEMON_NGINX_CONF=str(nginx), ISEMON_CERT_DIR=str(certs),
               ISEMON_FW_FILE4=str(WORK / 'fw4'), ISEMON_FW_FILE6=str(WORK / 'fw6'),
               ISEMON_RSYSLOG=str(WORK / 'none'))

    def helper(look=False):
        if look:
            (state / 'web' / 'look.ask').write_text('{}')
        subprocess.run([sys.executable, '-I', str(ROOT / 'deploy' / 'isemon_web.py')], env=env,
                       capture_output=True, timeout=120)
    helper(look=True)
    try:
        wr.firewall_page(True)
        ok('an allow of nginx\'s that is no address: the page draws', True)
    except Exception as e:                      # noqa: BLE001
        ok('an allow of nginx\'s that is no address: the page draws (%s)' % e, False)
    isemon.CONFIG['fw_confirm_min'] = 5
    refused('...and who may reach which page is not changed on trial (it could not go back)',
            wr.firewall_save, {'access': {'dashboard': {'any': True, 'from': []}}}, 'boss',
            kind=isemon.WebRootError)
    wr.firewall_save({'on': True, 'rules': [{'proto': 'tcp', 'port': '22', 'action': 'drop',
                                             'note': 'oops'}]}, 'boss')
    req = state / 'web' / 'request.json'
    ok('the request to root: the isemon account\'s alone', oct(req.stat().st_mode & 0o777), '0o600')
    helper()
    tr = np._get('fw:trial')
    tr['until'] = time.time() - 1
    np._put('fw:trial', tr)
    said = {}
    orig = np.fw_put_back

    def keep():
        try:
            said['k'] = np.answer('fw', 'keep', 'boss')
        except Exception as e:                  # noqa: BLE001
            said['k'] = 'refused: %s' % e

    def slow_put_back(trial, why):
        t = threading.Thread(target=keep)
        t.start()
        time.sleep(0.4)
        r = orig(trial, why)
        said['t'] = t
        return r
    np.fw_put_back = slow_put_back
    np.fw_trial_tick()
    said['t'].join(10)
    np.fw_put_back = orig
    ok('Keep pressed as the trial ran out: never "kept" of rules put back',
       (str(said.get('k')).startswith('refused'), np._get('fw:trial').get('done')), (True, 'back'))
    taken = state / 'web' / 'request.taken'
    for leftover in ('request.json',):
        try:
            (state / 'web' / leftover).unlink()
        except OSError:
            pass
    taken.write_text('{}')
    old = time.time() - 3600
    os.utime(str(taken), (old, old))
    ok('a request root never finished, past its deadline: not waited on', wr.pending(), False)
    taken.write_text('{}')
    ok('...a fresh one is', wr.pending(), True)
    helper()
    ok('...and root takes a leftover away', taken.exists(), False)
    (state / 'web' / 'look.ask').mkdir()
    (state / 'web' / 'look.ask' / 'x').write_text('x')
    helper()
    ok('a folder in place of look.ask: moved aside', (state / 'web' / 'look.ask').exists(), False)
    rows = ('*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -m state --state ESTABLISHED -j ACCEPT\n'
            ':MINE - [0:0]\n-A INPUT -j MINE\nCOMMIT\n')
    W2 = W
    got = W2.fw_into(rows, ['-A ISEMON -j RETURN'], 4) if W2.fw_into.__code__.co_argcount >= 3 \
        else W2.fw_into(rows, ['-A ISEMON -j RETURN'])
    ok('a chain declared after INPUT\'s first rule: nothing written twice',
       got.count('-A INPUT -m state --state ESTABLISHED -j ACCEPT'), 1)

    # ------------------------------------------------------------------------
    print('\nBackups of the configuration, put back on another machine')
    sA, A, dA = machine('A')
    dA.save_settings({'rbackup_password': PW, 'mikrotik_password': 'router-pw-1',
                      'rbackup_what': 'config', 'rbackup': 1}, by='boss')
    nas = WORK / 'nas'
    nas.mkdir()
    t = isemon.rb_save(A, {'kind': 'folder', 'path': str(nas), 'name': 'NAS'}, 'boss')
    isemon.rb_set_fields(A, t['id'], '', '', enabled=1)
    sm = isemon.rb_save(A, {'kind': 'smb', 'host': 'files.example.cz', 'share': 'b',
                            'user': 'u', 'password': 'smb-pass-9', 'name': 'Share'}, 'boss')
    isemon.rb_set_fields(A, sm['id'], '', '', enabled=0)
    guide = isemon.rb_restore_guide(A)
    ok('the guide is of the kind made now', ('-config.tar.gz.enc' in guide['file'],
                                             'the configuration only' in guide['md']), (True, True))
    run = isemon.rb_run(A, 'boss', daemon=dA)
    bundle = nas / run['file']
    kA = (sA / 'settings.key').read_text().strip()
    sB, B, dB = machine('B')
    dB.save_settings({'rbackup_password': PW, 'mikrotik_password': 'B-router-pw'}, by='admin')
    kB = (sB / 'settings.key').read_text().strip()
    got = isemon.rb_restore(B, str(bundle), PW, 'admin', dB)
    ok('put back', got.get('what'), 'config')
    ok('this machine\'s settings.key stays its own', (sB / 'settings.key').read_text().strip(), kB)
    isemon.Storage._unsealable = set()
    after = isemon.Storage(sB / 'isemon.db')
    ok('after a restart its passwords open', (after.settings_saved().get('mikrotik_password'),
                                             after.settings_saved().get('rbackup_password')),
       ('router-pw-1', PW))
    ok('...and the destinations\' too, sealed again with this machine\'s key',
       isemon.rb_secret(isemon.rb_target(after, sm['id']), 'password'), 'smb-pass-9')
    ok('kA and kB differ (the test means something)', kA != kB)

    print('\nA configuration this machine refuses changes nothing')
    sC, C, dC = machine('C')
    dC.save_settings({'rbackup_password': PW, 'mikrotik_password': 'C-pw'}, by='admin')
    kC = (sC / 'settings.key').read_text().strip()
    real_import = isemon.Daemon.import_config

    def no(self, *a, **k):
        raise ValueError('two settings that may not go together')
    isemon.Daemon.import_config = no
    try:
        isemon.rb_restore(C, str(bundle), PW, 'admin', dC)
        ok('refused', False)
    except isemon.RbError as e:
        ok('refused, and said nothing was put back', 'nothing was put back' in str(e))
    isemon.Daemon.import_config = real_import
    ok('...the key untouched', (sC / 'settings.key').read_text().strip(), kC)

    print('\nRetention, each kind on its own')

    class Tr(object):
        def __init__(self, names):
            self.names = list(names)

        def list(self):
            return [{'name': n, 'size': 1} for n in self.names]

        def delete(self, n):
            self.names.remove(n)
    s_, h_ = isemon.rb_site(), isemon.rb_host()
    full = 'isemon-backup-%s-%s-20261001-041500.tar.gz.enc' % (s_, h_)
    c1 = 'isemon-backup-%s-%s-20261002-041500-config.tar.gz.enc' % (s_, h_)
    c2 = 'isemon-backup-%s-%s-20261003-041500-config.tar.gz.enc' % (s_, h_)
    tr = Tr([full, c1, c2])
    isemon.rb_retain(tr, 2, 0, just=c2, sent=[full, c1, c2])
    ok('backups of the configuration never take a whole one away', full in tr.names)

    print('\nBackups: other fixes')
    old = {'kind': 'sftp', 'host': 'a.example.cz', 'password': isemon.rb_seal('x'), 'port': 22,
           'path': '/b'}
    refused('a password kept is not handed to another server',
            isemon.rb_checked, {'kind': 'sftp', 'host': 'b.example.cz', 'password': '•••',
                                'path': '/b'}, old, kind=ValueError)
    ok('...the same server keeps it', bool(isemon.rb_checked(
        {'kind': 'sftp', 'host': 'a.example.cz', 'password': '•••', 'path': '/b',
         'port': 2222}, old)['password']))
    refused('SCP: a folder the server\'s shell would read as more', isemon.rb_checked,
            {'kind': 'scp', 'host': 'a.b', 'path': '/b/$(id)'}, kind=ValueError)
    src = (ROOT / 'isemon.py').read_text()
    ok('an IPv6 server in brackets for scp and sftp, and -I for smbclient',
       ("self.sdest = '%s@[%s]'" in src, "(['-I', t['host']] if six else [])" in src),
       (True, True))
    ok('a restore and a backup never at once',
       ("rb_not_while(daemon, 'rbackup-restore'" in src and "rb_not_while(daemon, 'rbackup'," in src))
    ok('a refusal reads the body nobody read first', 'def spare_body(self)' in src and
       src.count('self.spare_body()') >= 4)
finally:
    shutil.rmtree(str(WORK), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
