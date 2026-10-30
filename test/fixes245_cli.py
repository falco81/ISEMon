#!/usr/bin/env python3
"""1.10.245: The otp logs over TLS from the command line and from
`isemon --console`, as the card has them (Settings - The OTP logs -
Encrypted receiving).

A daemon and its API in a folder of the test's own, with root's half
(isemon_web.py) run for real by a thread that plays isemon-web.path, with
rsyslog a small script and its files in folders of the test's (as
fixes245_otptls.py has them). The commands are run as `isemon` runs them,
against that API; the console's menu items are walked with their windows
answered by the test.

    ./test/fixes245_cli.py
"""
import argparse
import builtins
import contextlib
import io
import json
import os
import random
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

PW = 'correct-horse-battery'
ZIP_PATH = HERE / 'otp-tls' / 'isemon-tls.zip'

work = Path(tempfile.mkdtemp(prefix='isemon-245cli-'))
state = work / 'state'
(state / 'web').mkdir(parents=True)
etc = work / 'etc'
rsd = etc / 'rsyslog.d'
rsd.mkdir(parents=True)
(etc / 'rsyslog.conf').write_text('module(load="imuxsock")\n$IncludeConfig /etc/rsyslog.d/*.conf\n')
PLAIN = ('module(load="imudp")\ninput(type="imudp" port="514")\n'
         'module(load="imtcp")\ninput(type="imtcp" port="514")\n')
(rsd / '10-ise.conf').write_text(PLAIN)
PKI = etc / 'pki' / 'rsyslog' / 'otp'
CONF = rsd / '10-otp-tls.conf'
mods = work / 'lib64-rsyslog'
mods.mkdir()
(mods / 'lmnsd_gtls.so').write_text('')
rsyslogd = work / 'rsyslogd'
rsyslogd.write_text('#!/bin/sh\ncase "$1" in\n'
                    '  -v) echo "rsyslogd  8.2310.0 (aka 2023.10) compiled with:"; exit 0;;\n'
                    '  -N1) exit 0;;\nesac\nexit 1\n')
rsyslogd.chmod(0o755)
ZIP = work / 'in' / 'isemon-tls.zip'
ZIP.parent.mkdir()
shutil.copy(str(ZIP_PATH), str(ZIP))
PWFILE = work / 'in' / 'pw'
PWFILE.write_text(PW + '\n')
WRONG = work / 'in' / 'wrong'
WRONG.write_text('not-the-passphrase\n')

os.environ['ISEMON_WEB_HELPER'] = '1'
for k in ('ISEMON_ZIP_PASSPHRASE', 'ISEMON_KEY_PASSPHRASE'):
    os.environ.pop(k, None)
HELPER_ENV = dict(os.environ, ISEMON_STATE=str(state), ISEMON_WEB_NO_SERVICES='1',
                  ISEMON_RSYSLOG='%s:%s' % (etc / 'rsyslog.conf', rsd),
                  ISEMON_OTPTLS_CONF=str(CONF), ISEMON_OTPTLS_DIR=str(PKI),
                  ISEMON_RSYSLOGD=str(rsyslogd), ISEMON_RSYSLOG_MODDIR=str(mods),
                  ISEMON_NGINX_CONF=str(work / 'none.conf'))
HELPER = ROOT / 'deploy' / 'isemon_web.py'

import isemon                                        # noqa: E402

PASS = FAIL = 0
PORT = 20100 + random.randint(0, 90)          # a range of its own: tests run side by side


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


isemon.STATE_DIR = state
isemon.DB_FILE = state / 'd.db'
isemon.BACKUP_DIR = state / 'backups'
isemon.DUMP_DIR = state / 'dumps'
isemon.RUN_DIR = state
isemon.LOG_DIR = state
isemon.CONFIG_FILE = state / 'config.json'
isemon._LOG_PATH = state / 'd.log'
isemon.TOKEN_FILE = state / 'api-token'
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'api_port': PORT, 'geo': 0, 'mikrotik1': 0})
(state / 'config.json').write_text(json.dumps({'db_engine': 'sqlite'}))
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)
STOP = threading.Event()


def path_unit():
    """isemon-web.path: what is asked handed to root's helper at once."""
    while not STOP.is_set():
        if any(os.path.lexists(str(state / 'web' / f)) for f in ('otptls.ask', 'look.ask')):
            subprocess.run(['python3', '-I', str(HELPER)], env=HELPER_ENV, capture_output=True)
        time.sleep(0.05)


def run(fn, answers=(), **kw):
    """One command as `isemon` runs it: (exit code, what it printed)."""
    ns = dict(json=False, yes=False, out=None, passphrase_file=None, otp_tls=False,
              otp_tls_import=None, otp_tls_make=None, otp_tls_set=False, otp_tls_off=False,
              otp_tls_port=None, otp_tls_nodes=None, otp_tls_mutual=None, otp_tls_ca=None)
    ns.update(kw)
    args = argparse.Namespace(**ns)
    buf = io.StringIO()
    asked = []
    queue = list(answers)
    was = builtins.input

    def typed(prompt=''):
        asked.append(prompt)
        return queue.pop(0) if queue else ''
    builtins.input = typed
    try:
        with contextlib.redirect_stdout(buf):
            rc = fn(args, isemon.Palette(False, buf), store)
    finally:
        builtins.input = was
    run.asked = asked
    return rc, buf.getvalue()


def sq(text):
    return ' '.join(text.split())


def settle(secs=30):
    end = time.time() + secs
    while time.time() < end and (isemon.OTPTLS_WORK['busy'] or isemon.OTPTLS_WORK['queue']):
        time.sleep(0.1)


try:
    daemon.add_user('boss', 'a-long-enough-password', 'fulladmin', by='test')
    api = isemon.ApiServer(daemon, PORT)
    api.start()
    time.sleep(0.4)
    (state / 'api-token').write_text(isemon.API_TOKEN)
    threading.Thread(target=path_unit, daemon=True).start()

    # ------------------------------------------------------------------------
    print('isemon --otp-tls before anything')
    rc, out = run(isemon.cmd_otp_tls)
    ok('read afresh: off, nothing there', (rc, 'encrypted receiving off' in sq(out),
                                           'certificate none yet' in sq(out)), (0, True, True))
    ok('...rsyslog\'s version and driver', 'rsyslog 8.2310, TLS driver gtls' in sq(out))
    ok('...the plain input on 514 said to be kept', '514/tcp' in out and '514/udp' in out)
    rc, out = run(isemon.cmd_otp_tls, json=True)
    v = json.loads(out)
    ok('--otp-tls --json: the view the card reads', (rc, v['ok'], v['read'], v['on'],
                                                     v['version']), (0, True, True, False,
                                                                     '8.2310'))

    # ------------------------------------------------------------------------
    print('\nisemon --otp-tls-import')
    rc, out = run(isemon.cmd_otp_tls_import, answers=['no'], otp_tls_import=str(ZIP),
                  passphrase_file=str(PWFILE))
    ok('shown first: the certificate, its issuer, until when',
       ('isemon.example.net, 192.0.2.10' in out, 'CN=otp cluster authority' in out,
        'until' in out), (True, True, True))
    ok('...what otp\'s file says', 'port 6514, mutual TLS, nodes otp1, otp2' in out)
    ok('...asked, and no is no', (rc, len(run.asked), 'nothing was done' in out, CONF.exists()),
       (1, 1, True, False))
    ok('...the passphrase nowhere in what it said', PW in out, False)

    rc, out = run(isemon.cmd_otp_tls_import, otp_tls_import=str(ZIP),
                  passphrase_file=str(WRONG), yes=True)
    ok('a wrong passphrase: said, nothing done',
       (rc, 'the passphrase is not the one the file was made with' in out, CONF.exists()),
       (1, True, False))

    os.environ['ISEMON_ZIP_PASSPHRASE'] = PW
    try:
        rc, out = run(isemon.cmd_otp_tls_import, otp_tls_import=str(ZIP), yes=True)
    finally:
        os.environ.pop('ISEMON_ZIP_PASSPHRASE', None)
    ok('--yes, the passphrase from ISEMON_ZIP_PASSPHRASE: followed to the end',
       (rc, 'the otp logs are received over TLS on 6514/tcp' in out, run.asked), (0, True, []))
    ok('...what root said', any('6514/tcp' in l and 'otp1, otp2' in l for l in out.splitlines()))
    ok('...put in: mutual, the nodes from otp\'s file',
       ('PermittedPeer=["otp1", "otp2"]' in CONF.read_text(),
        (rsd / '10-ise.conf').read_text()), (True, PLAIN))
    ok('...the passphrase never said', PW in out, False)
    ok('...nor in the log or the database', any(
        PW.encode() in f.read_bytes() for f in state.rglob('*') if f.is_file()), False)

    rc, out = run(isemon.cmd_otp_tls)
    ok('--otp-tls now: on, its port, mode, nodes, certificate, how',
       (rc, 'encrypted receiving on' in sq(out), 'port 6514/tcp' in sq(out),
        'mutual TLS - only the nodes named' in out, 'nodes otp1, otp2' in sq(out),
        'from the file otp made' in out, 'the last change' in out), (0,) + (True,) * 6)

    rc, out = run(isemon.cmd_otp_tls_import, otp_tls_import=str(ZIP),
                  passphrase_file=str(PWFILE), yes=True, otp_tls_port=6600,
                  otp_tls_mutual='no')
    ok('given here: the port and the mode otp\'s file said overridden',
       (rc, 'port="6600"' in CONF.read_text(), 'AuthMode="anon"' in CONF.read_text()),
       (0, True, True))
    rc, out = run(isemon.cmd_otp_tls_import, otp_tls_import=str(ZIP),
                  passphrase_file=str(PWFILE), json=True)
    ok('--json without --yes: asks nothing, does nothing',
       (rc, json.loads(out)['ok'], run.asked), (1, False, []))

    # ------------------------------------------------------------------------
    print('\nisemon --otp-tls-set')
    rc, out = run(isemon.cmd_otp_tls_set, otp_tls_port=6514, otp_tls_mutual='yes',
                  otp_tls_nodes='otp1, otp2 otp3')
    ok('the nodes, the port and the mode changed', (rc, 'changed: 6514/tcp' in out,
                                                    'PermittedPeer=["otp1", "otp2", "otp3"]'
                                                    in CONF.read_text()), (0, True, True))
    rc, out = run(isemon.cmd_otp_tls_set, otp_tls_nodes='bad name!')
    ok('root refuses a name that is none: said', (rc, 'root said' in out,
                                                  'is not a name' in out), (1, True, True))

    # ------------------------------------------------------------------------
    print('\nisemon --otp-tls-make')
    otp_ca = work / 'in' / 'otp-ca.pem'
    otp_ca.write_bytes(isemon.otp_zip_open(ZIP.read_bytes(), PW)['ca.pem'])
    rc, out = run(isemon.cmd_otp_tls_make, otp_tls_make='isemon.example.net,192.0.2.10',
                  otp_tls_ca=str(otp_ca), otp_tls_nodes='otp1 otp2')
    ok('made and put in: this machine\'s authority printed',
       (rc, '-----BEGIN CERTIFICATE-----' in out, 'PRIVATE' in out), (0, True, False))
    ok('...and how to paste it into otp', 'Settings → isemon → Encrypted sending → "isemon has '
       'one from its own CA"' in out)
    ok('...mutual, with otp\'s authority', 'AuthMode="x509/name"' in CONF.read_text())
    there = work / 'in' / 'there.pem'
    there.write_text('mine')
    rc, out = run(isemon.cmd_otp_tls_make, otp_tls_make='isemon.example.net', out=str(there))
    ok('--out over a file there: refused, nothing made', (rc, there.read_text(),
                                                          'never written over' in out),
       (1, 'mine', True))
    newf = work / 'in' / 'isemon-ca.pem'
    rc, out = run(isemon.cmd_otp_tls_make, otp_tls_make='isemon.example.net', out=str(newf))
    ok('--out: the authority into the file', (rc, newf.read_text().startswith(
        '-----BEGIN CERTIFICATE-----'), 'BEGIN CERTIFICATE' in out), (0, True, False))
    ok('...not mutual without otp\'s authority', 'AuthMode="anon"' in CONF.read_text())
    rc, out = run(isemon.cmd_otp_tls_make, otp_tls_make='isemon.example.net',
                  otp_tls_mutual='yes')
    ok('mutual without otp\'s authority: the daemon\'s refusal', (rc, 'otp\'s authority' in out),
       (1, True))

    # ------------------------------------------------------------------------
    print('\nisemon --otp-tls-off')
    rc, out = run(isemon.cmd_otp_tls_off, answers=['no'])
    ok('asked first, no is no', (rc, 'nothing was done' in out, CONF.exists()), (1, True, True))
    rc, out = run(isemon.cmd_otp_tls_off, yes=True)
    ok('--yes: switched off, the plain input as it was',
       (rc, 'switched off' in out, CONF.exists(), (rsd / '10-ise.conf').read_text()),
       (0, True, False, PLAIN))
    rc, out = run(isemon.cmd_otp_tls_off, yes=True)
    ok('off already: said, nothing asked of root', (rc, 'nothing to switch off' in out),
       (0, True))

    print('\nWithout root\'s half')
    os.environ['ISEMON_WEB_HELPER'] = '0'
    rc, out = run(isemon.cmd_otp_tls)
    ok('--otp-tls says what to run', (rc, './install.sh --upgrade' in out), (1, True))
    rc, out = run(isemon.cmd_otp_tls_off, yes=True)
    ok('--otp-tls-off says what to run', (rc, './install.sh --upgrade' in out), (1, True))
    os.environ['ISEMON_WEB_HELPER'] = '1'

    # ------------------------------------------------------------------------
    print('\nThe parser, --help, and the passphrase never on the command line')
    parser = isemon.cli_parser()
    for argv in (['--otp-tls'], ['--otp-tls', '--json'],
                 ['--otp-tls-import', '/root/isemon-tls.zip', '--passphrase-file', '/root/pp',
                  '--yes'],
                 ['--otp-tls-import', '/root/z.zip', '--otp-tls-port', '6600',
                  '--otp-tls-nodes', 'otp1 otp2', '--otp-tls-mutual', 'no'],
                 ['--otp-tls-make', 'a.example,192.0.2.1', '--otp-tls-ca', '/root/ca.pem',
                  '--out', '/root/isemon-ca.pem'],
                 ['--otp-tls-set', '--otp-tls-nodes', ''], ['--otp-tls-off', '--yes']):
        try:
            parser.parse_args(argv)
            ok('isemon %s parses' % ' '.join(argv[:2]), True)
        except SystemExit:
            ok('isemon %s parses' % ' '.join(argv[:2]), False)
    for argv in (['--otp-tls-set', '--otp-tls-mutual', 'maybe'],):
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                parser.parse_args(argv)
            ok('isemon %s is refused' % ' '.join(argv[:3]), False)
        except SystemExit:
            ok('isemon %s is refused' % ' '.join(argv[:3]), True)
    rc, out = run(isemon.cmd_otp_tls_import, **vars(parser.parse_args(['--otp-tls-import', str(ZIP), '--passphrase', PW])))
    ok('a passphrase typed on the command line anyway (--passphrase, taken by argparse for '
       '--passphrase-file): refused, and not printed back', (rc, PW in out), (1, False))
    got = subprocess.run([sys.executable, str(ROOT / 'isemon.py'), '--help'],
                         capture_output=True, text=True)
    ok('--help works, and has them all', (got.returncode, all(
        x in got.stdout for x in ('--otp-tls ', '--otp-tls-import', '--otp-tls-make',
                                  '--otp-tls-set', '--otp-tls-off', '--otp-tls-port',
                                  '--otp-tls-nodes', '--otp-tls-mutual', '--otp-tls-ca'))),
       (0, True))
    got = subprocess.run([sys.executable, str(ROOT / 'isemon.py'), '--otp-tls-port', '6514'],
                         capture_output=True, text=True)
    ok('--otp-tls-port alone does nothing, and says so',
       (got.returncode, 'nothing was asked for' in got.stderr), (2, True))

    # ------------------------------------------------------------------------
    print('\nThe console: Network, time and power')
    known = isemon.cli_options()

    class Dry(isemon.Console):
        def __init__(self):
            super(Dry, self).__init__(isemon.Palette(False))
            self.ran, self.picks, self.asks, self.items, self.said = [], {}, {}, None, []

        def out(self, *args):
            if args[0] == '--otp-tls':
                return {'on': True, 'port': 6514, 'auth': 'x509/name', 'peers': ['otp1']}
            return None

        def sub(self, title_, items):
            self.items = (title_, items)

        def choose(self, title_, options, words='', cur=0):
            want = self.picks.get(title_)
            vals = [o[0] for o in options]
            return want if want in vals else (vals[cur] if vals and want is None else None)

        def confirm(self, title_, words, yes='Yes', no='No', danger=False):
            self.said.append((title_, words))
            return True

        def ask_one(self, title_, label, value='', help_='', need=True, secret=False,
                    check=None):
            got = self.asks.get(label, value)
            if check and got is not None and check(got, {}):
                return None
            return got

        def note(self, *a, **k):
            self.said.append(a)

        def working(self, *a):
            pass

        def act(self, *args, env=None, title=None, quiet_ok=None):
            self.ran.append((tuple(str(a) for a in args), env, 'act'))

        def show_live(self, *args, env=None):
            self.ran.append((tuple(str(a) for a in args), env, 'live'))

        def go_plain(self, fn):
            return fn()

    d = Dry()
    d.m_machine()
    title_, items = d.items
    names = {it[1]: it for it in items}
    ok('The otp logs over TLS in it, as 8', names.get('The otp logs over TLS', ('',))[0], '8')

    def walk(picks=None, asks=None):
        d.ran, d.said = [], []
        d.picks, d.asks = picks or {}, asks or {}
        names['The otp logs over TLS'][2]()
        return list(d.ran)
    T = 'The otp logs over TLS'
    ok('> show', walk({T: 'show'}), [(('--otp-tls',), None, 'act')])
    got = walk({T: 'import', 'Put in the file otp made': 'file'},
               {'the file': str(ZIP), 'the passphrase': PW})
    ok('> import, as otp\'s file says: confirmed, the passphrase by the environment only',
       (got, len(d.said)), ([(('--otp-tls-import', str(ZIP), '--yes'),
                              {'ISEMON_ZIP_PASSPHRASE': PW}, 'act')], 1))
    ok('...never on the command line', any(PW in a for a in got[0][0]), False)
    got = walk({T: 'import', 'Put in the file otp made': 'own'},
               {'the file': str(ZIP), 'the passphrase': PW, 'the port': '6600',
                'the nodes': 'otp1 otp2'})
    ok('> import, said here', got[0][0], ('--otp-tls-import', str(ZIP), '--otp-tls-port', '6600',
                                         '--otp-tls-mutual', 'yes', '--otp-tls-nodes',
                                         'otp1 otp2', '--yes'))
    ok('...no file: nothing run', walk({T: 'import'}, {'the file': str(work / 'nope.zip'),
                                                      'the passphrase': PW}), [])
    ok('...no passphrase: nothing run', walk({T: 'import'}, {'the file': str(ZIP),
                                                            'the passphrase': ''}), [])
    newca = str(work / 'in' / 'console-ca.pem')
    got = walk({T: 'make'}, {'the names': 'isemon.example.net', 'otp\'s authority': str(otp_ca),
                             'into the file': newca})
    ok('> make', got, [(('--otp-tls-make', 'isemon.example.net', '--otp-tls-port', '6514',
                         '--otp-tls-mutual', 'yes', '--otp-tls-nodes', 'otp1',
                         '--otp-tls-ca', str(otp_ca), '--out', newca), None, 'act')])
    ok('...never over a file there', walk({T: 'make'}, {'the names': 'a', 'otp\'s authority': '',
                                                       'into the file': str(there)}), [])
    got = walk({T: 'set', 'Who may send': 'no'})
    ok('> change, not mutual', got, [(('--otp-tls-set', '--otp-tls-port', '6514',
                                       '--otp-tls-mutual', 'no'), None, 'act')])
    got = walk({T: 'off'})
    ok('> off: confirmed first', (got, len(d.said)),
       ([(('--otp-tls-off', '--yes'), None, 'act')], 1))
    all_args = []
    for picks, asks in (
            ({T: 'show'}, {}),
            ({T: 'import', 'Put in the file otp made': 'own'},
             {'the file': str(ZIP), 'the passphrase': PW, 'the nodes': 'otp1'}),
            ({T: 'make'}, {'the names': 'a b', 'otp\'s authority': str(otp_ca),
                           'into the file': newca}),
            ({T: 'make', 'Who may send': 'no'},
             {'the names': 'a', 'otp\'s authority': '', 'into the file': newca}),
            ({T: 'set'}, {'the nodes': ''}), ({T: 'off'}, {})):
        all_args += [a for a, _e, _h in walk(picks, asks)]
    ok('every command the items run is in this version',
       [a for a in all_args if isemon.cli_missing(a, known)], [])
    bad = []
    for a in all_args:
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                parser.parse_args(list(a))
        except SystemExit:
            bad.append(a)
    ok('...and parses', bad, [])
finally:
    STOP.set()
    time.sleep(0.3)
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
