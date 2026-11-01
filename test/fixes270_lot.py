#!/usr/bin/env python3
"""1.10.270: the failed and passed rows of a lot of records written together
(`OwedRows`) - on PostgreSQL one statement for the lot's rows instead of an
INSERT a record, which was half of what a record cost there.

Held against the rows written one by one: the same stream - VPN refusals that
earn bans and go on after them, sign-ins, 802.1X and MAB, TACACS+, the same
records twice in one lot and again in the next - put through the real reader
both ways must leave the same rows, the same bans, the same events and the
same counts. On the file always (where it is switched on for this check
only), and on a PostgreSQL server when `ISEMON_TEST_POSTGRES` names one
(`host:port:name:user:password`; its tables are dropped first).

    ./test/fixes270_lot.py
"""
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
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


def zone(ts):
    z = time.strftime('%z', time.localtime(ts))
    return z[:3] + ':' + z[3:]


BASE = time.time() - 1800
VPN = ('Protocol=Radius, NetworkDeviceName=FTD-VPN, NAS-IP-Address=172.29.14.81, '
       'Called-Station-ID=198.51.100.200, Calling-Station-ID=%s, NAS-Port-Type=Virtual, '
       'Tunnel-Client-Endpoint=(tag=0) %s, CVPN3000/ASA/PIX7x-Tunnel-Group-Name=AnyConnect_ADM, '
       'FailureReason=22056 Subject not found in the applicable identity store')
VPN_OK = ('Protocol=Radius, NetworkDeviceName=FTD-VPN, NAS-IP-Address=172.29.14.81, '
          'Calling-Station-ID=%s, NAS-Port-Type=Virtual, Tunnel-Client-Endpoint=(tag=0) %s, '
          'CVPN3000/ASA/PIX7x-Tunnel-Group-Name=AnyConnect_ADM, '
          'SelectedAuthorizationProfiles=VPN_FULL')
DOT1X = ('Protocol=Radius, NetworkDeviceName=swje4np, User-Name=host/pc%d, '
         'NAS-IP-Address=172.29.2.27, NAS-Port=50104, Service-Type=Framed, '
         'Calling-Station-ID=98-FC-84-E0-29-%02X, NAS-Port-Type=Ethernet, '
         'NAS-Port-Id=GigabitEthernet1/0/4, RadiusFlowType=Wired802_1x, '
         'FailureReason=12321 PEAP failed SSL/TLS handshake')
MAB = ('Protocol=Radius, NetworkDeviceName=swje2np, User-Name=98fc84e116%02x, '
       'NAS-IP-Address=172.29.2.23, NAS-Port=50141, Service-Type=Call Check, '
       'Calling-Station-ID=98-FC-84-E1-16-%02X, NAS-Port-Type=Ethernet, '
       'NAS-Port-Id=GigabitEthernet1/0/41, cisco-av-pair=method=mab, RadiusFlowType=WiredMAB, '
       'FailureReason=15039 Rejected per authorization profile')
TACACS = ('Protocol=Tacacs, NetworkDeviceName=vs23a, Type=Authentication, Action=Login, '
          'Remote-Address=192.168.251.%d, SelectedShellProfile=Admin_LVL15, '
          'FailureReason=13017 Received TACACS+ packet with incorrect password')


def line(kind, seq, at, user, rest):
    cat = 'CISE_Failed_Attempts' if kind == 'failed' else 'CISE_Passed_Authentications'
    said = 'Failed-Attempt: Authentication failed' if kind == 'failed' \
        else 'Passed-Authentication: Authentication succeeded'
    stamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(at)) + '.500 ' + zone(at)
    head = ('%s 0075245450 5400 NOTICE %s, ConfigVersionId=126, Device IP Address=172.29.2.23, '
            'UserName=%s, %s, AcsSessionID=isea/579122599/%d,' % (stamp, said, user, rest, seq))
    return '%s isea %s %010d 1 0 %s' % (time.strftime('%b %d %H:%M:%S', time.localtime(at)),
                                        cat, seq, head)


def stream():
    """[(kind, [lines])] - what the reader is handed, call by call."""
    out = []
    seq = 1000
    lot = []
    for n in range(400):
        seq += 1
        at = BASE + n
        m = n % 8
        if m in (0, 1, 2):
            ip = '203.0.113.%d' % (1 + n % 12)        # twelve that try and try
            lot.append(('failed', line('failed', seq, at, 'user%d' % (n % 5), VPN % (ip, ip))))
        elif m == 3:
            ip = '198.51.100.%d' % (1 + n % 50)
            lot.append(('passed', line('passed', seq, at, 'staff%d' % (n % 40), VPN_OK % (ip, ip))))
        elif m == 4:
            lot.append(('failed', line('failed', seq, at, 'host/pc%d' % n, DOT1X % (n, n % 256))))
        elif m == 5:
            lot.append(('failed', line('failed', seq, at, '98fc84e116%02x' % (n % 256),
                                       MAB % (n % 256, n % 256))))
        elif m == 6:
            lot.append(('failed', line('failed', seq, at, 'admin', TACACS % (1 + n % 7))))
        else:
            ip = '198.51.100.%d' % (1 + n % 50)
            lot.append(('passed', line('passed', seq, at, 'staff%d' % (n % 40), VPN_OK % (ip, ip))))
    # The same records again inside the lot, and the first ones once more
    # in the next.
    lot += lot[40:60]
    failed = [x for k, x in lot if k == 'failed']
    passed = [x for k, x in lot if k == 'passed']
    out.append(('failed', failed))
    out.append(('passed', passed))
    out.append(('failed', failed[:30] + [line('failed', 9001, BASE + 900, 'user1',
                                               VPN % ('203.0.113.1', '203.0.113.1'))]))
    return out


def run(store, daemon):
    news = [daemon.read_records(lines, kind=kind) for kind, lines in stream()]
    q = lambda sql: [tuple(r) for r in store.db.execute(sql).fetchall()]   # noqa: E731
    return {
        'new': news,
        'failed': q('SELECT session, ip, username, kind, code FROM failed ORDER BY session'),
        'passed': q('SELECT session, ip, username, kind FROM passed ORDER BY session'),
        'bans': q('SELECT ip, why, auto, hits FROM blocked ORDER BY ip'),
        'ban history': q('SELECT ip, why, hits FROM blocked_log ORDER BY ip, ts'),
        'events': q("SELECT kind, level, detail FROM events WHERE kind <> 'settings' "
                    'ORDER BY id'),
    }


def fresh(engine=None):
    folder = Path(tempfile.mkdtemp(prefix='isemon-270-'))
    isemon.STATE_DIR = folder
    isemon.DB_FILE = folder / 'lot.db'
    isemon.BACKUP_DIR = folder / 'backups'
    isemon.DUMP_DIR = folder / 'dumps'
    isemon.RUN_DIR = folder
    isemon.LOG_DIR = folder
    isemon._LOG_PATH = folder / 'lot.log'
    isemon.CONFIG.update({
        'blacklist': 1, 'block_mode': 'temporary', 'block_tries': 3,
        'block_window_min': 60, 'block_lots': 0, 'block_bogus_tries': 0,
        'block_ladder': '15, 60, forever', 'feeds_ban': 0, 'geo': 0,
        'mikrotik_host': '', 'watch_devices': '', 'passed_devices': '',
        'never_block': '', 'never_block_countries': '', 'read_passed': 1,
        'judge_max_age_h': 0, 'debug': False, 'mikrotik1': 0,
    })
    if engine:
        isemon.Storage.ENGINE = engine
        far = isemon.Storage()
        for table in isemon.Dialect.schema_tables(isemon.SCHEMA):
            far.db.execute('DROP TABLE IF EXISTS %s CASCADE' % far.dialect.ident(table))
        far.close()
        store = isemon.Storage()
    else:
        isemon.Storage.ENGINE = None
        store = isemon.Storage(isemon.DB_FILE)
    daemon = isemon.Daemon(store)
    daemon._spare_from = None
    return folder, store, daemon


def both(engine, label):
    """The stream with the rows written one by one, and together."""
    got = {}
    paid = {'n': 0}
    real_pay = isemon.OwedRows.pay

    def counted(self):
        if self.rows:
            paid['n'] += 1
        try:
            return real_pay(self)
        finally:
            if self.spoiled:
                spoiled['n'] += 1
    real_begin = isemon.Storage.owe_begin
    spoiled = {'n': 0}

    def blind_begin(self, db, records):
        # As if another connection wrote the rows already there after they
        # were looked up: none of them is known to be there.
        owe = real_begin(self, db, records)
        if owe is not None:
            for t in owe.there:
                owe.there[t].clear()
        return owe
    hows = ('one by one', 'together', 'together, its first writing refused',
            'together, rows written meanwhile by another connection')
    for how in hows:
        isemon.Storage.OWE_ENGINES = () if how == 'one by one' else ('postgres', 'sqlite')
        refused = {'left': 1 if 'refused' in how else 0}
        isemon.Storage.owe_begin = blind_begin if 'meanwhile' in how else real_begin

        def pay(self):
            if refused['left'] and self.rows:
                refused['left'] -= 1
                raise isemon.StorageError('refused for the check')
            return counted(self)
        isemon.OwedRows.pay = pay
        folder, store, daemon = fresh(engine)
        try:
            got[how] = run(store, daemon)
        finally:
            isemon.OwedRows.pay = real_pay
            isemon.Storage.owe_begin = real_begin
            store.close()
            shutil.rmtree(str(folder), ignore_errors=True)
    one = got['one by one']
    ok('%s: the stream did what it is there to do - bans, rows, sign-ins' % label,
       (len(one['bans']) >= 5, len(one['failed']) > 250, len(one['passed']) > 80,
        one['new'][2] == 1), (True, True, True, True))
    for how in hows[1:]:
        for key in ('new', 'failed', 'passed', 'bans', 'ban history', 'events'):
            ok('%s, %s: %s the same as one by one' % (label, how, key), got[how][key], one[key])
    ok('%s: ...and the rows were written together' % label, paid['n'] > 0)
    ok('%s: rows another connection wrote meanwhile were found out, and the lot taken again'
       % label, spoiled['n'] > 0)


try:
    print('On the file (switched on here for the check)')
    both(None, 'the file')
    pg = os.environ.get('ISEMON_TEST_POSTGRES', '')
    print('\nOn PostgreSQL')
    if not pg:
        print('  --    no ISEMON_TEST_POSTGRES, so nothing was tried')
    elif not isemon.DIALECTS['postgres'].driver_ready()[0]:
        print('  --    %s' % isemon.DIALECTS['postgres'].driver_ready()[1])
    else:
        host, _, rest = pg.partition(':')
        port, _, rest = rest.partition(':')
        name, _, rest = rest.partition(':')
        user, _, word = rest.partition(':')
        both({'engine': 'postgres', 'host': host or '127.0.0.1', 'port': int(port or 5432),
              'name': name or 'isemon', 'user': user or 'isemon', 'password': word,
              'timeout': 10}, 'PostgreSQL')

    print('\nA session as it lands')
    ok('without its NULs, as every value is written', (isemon.OwedRows.key('a\x00b'),
                                                       isemon.OwedRows.key(None)), ('ab', None))

    print('\nWhere it is done')
    isemon.Storage.OWE_ENGINES = ('postgres',)
    ok('on PostgreSQL only: the file and MariaDB write each row as it comes',
       isemon.Storage.OWE_ENGINES, ('postgres',))
    src = (HERE.parent / 'isemon.py').read_text()
    ok('any statement naming failed or passed has the held rows written first',
       src.count('if owed is not None and owed.rows and not owed.busy and '
                 'OWED_TABLES.search(sql):'), 2)
    ok('...written before the lot is committed, and a refusal takes the lot again carefully',
       ('owe.pay()\n                        except Exception as e:\n'
        '                            raise TakeCarefully(str(e)) from e' in src,
        "owe = None if careful else store.owe_begin(" in src), (True, True))
finally:
    isemon.Storage.ENGINE = None
    isemon.Storage.OWE_ENGINES = ('postgres',)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
