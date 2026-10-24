#!/usr/bin/env python3
"""1.10.200: the fixes of the fourth review round.

    ./test/fixes200.py
"""
import re
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


def raises(what, fn, kind=Exception):
    try:
        fn()
    except kind:
        ok(what, True)
        return
    except Exception as e:
        ok(what, type(e).__name__, kind.__name__)
        return
    ok(what, 'no error', 'an error')


page = (HERE.parent / 'web' / 'index.php').read_text(encoding='utf-8')
folder = tempfile.mkdtemp(prefix='isemon-200-')
isemon.STATE_DIR = Path(folder)
isemon.DB_FILE = Path(folder) / 'c.db'
isemon.BACKUP_DIR = Path(folder) / 'b'
isemon.DUMP_DIR = Path(folder) / 'd'
isemon.RUN_DIR = Path(folder)
isemon.LOG_DIR = Path(folder)
isemon._LOG_PATH = Path(folder) / 'c.log'
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0, 'mikrotik_sync': 0})
store = isemon.Storage(isemon.DB_FILE)

print('\nLOWER() for every letter')
ok('the function', isemon.sqlite_lower('ŽLUŤOUČKÝ Kůň'), 'žluťoučký kůň')
ok('...leaves what is not text', isemon.sqlite_lower(None), None)
if store.dialect.name == 'sqlite':
    ok('...and is what SQLite uses', store.db.execute("SELECT LOWER('ČEŘ')").fetchone()[0],
       'čeř')

print('\nThe RADIUS doors')
ok('a prompt at a switch on a Virtual port is not the VPN',
   isemon.ise_flow({'NAS-Port-Type': ['Virtual'], 'Service-Type': ['NAS Prompt']}), 'other')
ok('...nor is Administrative',
   isemon.ise_flow({'NAS-Port-Type': ['Virtual'], 'Service-Type': ['Administrative']}), 'other')
ok('...but a tunnel group is the VPN whatever it says',
   isemon.ise_flow({'NAS-Port-Type': ['Virtual'], 'Service-Type': ['NAS Prompt'],
                    'CVPN3000/ASA/PIX7x-Tunnel-Group-Name': ['RA']}), 'vpn')
ok('...and Virtual alone still is', isemon.ise_flow({'NAS-Port-Type': ['Virtual']}), 'vpn')

print('\nA country in the find box')
cols = store.columns_of(isemon.LIST_TABLES['failed'])
q = isemon.ListQuery('failed', 'country:cz', ident=store.dialect.ident, columns=cols)
ok('two letters', q.args, ['CZ'])
raises('...a name is refused, not searched as its first two',
       lambda: isemon.ListQuery('failed', 'country:China', ident=store.dialect.ident,
                                columns=cols), isemon.ListQueryError)
q = isemon.ListQuery('failed', 'country:c*', ident=store.dialect.ident, columns=cols)
ok('...and a wildcard still works', bool(q.sql), True)
q = isemon.ListQuery('failed', 'country:x', ident=store.dialect.ident, columns=cols)
ok('...and one letter is taken as before', q.args, ['X'])

print('\nA FortiGate tunnel id given to somebody else')
T0 = 1790000000.0


def vrow(ts, user, ip, action):
    return {'ts': ts, 'fw': 'fg1', 'dev': 'fg1', 'area': 'client-vpn', 'type': 'event',
            'sub': 'vpn', 'action': action, 'verdict': '', 'srcip': ip, 'dstip': '',
            'user': user, 'msg': '', 'sent': 1, 'rcvd': 1, 'duration': 0,
            'fields': {'tunnelid': '7', 'msgid': ''}}


got = isemon.fw_vpn_fold([vrow(T0 - 600, 'alice', '198.51.100.1', 'tunnel-up'),
                          vrow(T0 - 300, 'bob', '198.51.100.2', 'tunnel-up')], T0)
ok('the second person is a session of their own', [c['user'] for c in got['clients']], ['bob'])
ok('...and the first one ended', got['ended_clients'], 1)
got = isemon.fw_vpn_fold([vrow(T0 - 600, 'alice', '198.51.100.1', 'tunnel-up'),
                          vrow(T0 - 300, 'alice', '198.51.100.1', 'tunnel-stats')], T0)
ok('the same person on the same tunnel is still one session',
   ([c['user'] for c in got['clients']], got['ended_clients']), (['alice'], 0))

print('\nwinsec_zone')
raises('"local" is refused', lambda: isemon.check_setting('winsec_zone', 'local'), ValueError)
ok('...an empty one is still taken', isemon.check_setting('winsec_zone', '') in ('', None), True)

print('\nAccounts by their whole names')
ok('svc.adsync is not svc', isemon.win_account_name('svc.adsync') ==
   isemon.win_account_name('svc.helpdesk'), False)
ok('...a machine is still cut', isemon.win_account_name('host/pc1.corp.int') ==
   isemon.win_account_name('PC1$'), True)
ok('the sort is redone', isemon.Storage.WIN_SORT_VERSION if hasattr(isemon.Storage, 'WIN_SORT_VERSION') else isemon.Daemon.WIN_SORT_VERSION, 5)

print('\nErasing the bans')
store.block('203.0.113.77', until=time.time() + 3600, why='test', auto=True)
store.erase(['bans'])
rows = [dict(r) for r in store.db.execute(
    "SELECT ip, what, why FROM block_events WHERE ip = '203.0.113.77'")]
ok('a "let back in" is written for who was banned',
   [(r['what'], r['why']) for r in rows][-1:], [('let back in', 'erased')])

print('\nA list with a byte-order mark')


class Answer(object):
    def __init__(self, body):
        self.body, self.headers = body, {'Content-Length': str(len(body))}

    def read(self, n=-1):
        if n is None or n < 0:
            n = len(self.body)
        part, self.body = self.body[:n], self.body[n:]
        return part

    def getheader(self, name, default=None):
        return self.headers.get(name, default)

    def info(self):
        return self.headers


try:
    got = list(isemon.lines_of(Answer('﻿1.2.3.4\n5.6.7.8\n'.encode('utf-8'))))
    ok('the first entry is kept', [g.strip() for g in got][:2], ['1.2.3.4', '5.6.7.8'])
except Exception as e:
    ok('the first entry is kept', repr(e), 'no error')

print('\nThe page')
ok('the domain bar is clipped to its chart',
   'var dh = Math.min(h, Math.max(1, h * (split.domain / against)));' in page)
ok('a forced password change has a way out',
   'change.onclick = function () { myPassword(false); }' in page)
ok('the events list can show the watched bans and the whitelist',
   bool(re.search(r"value=\"watch\"", page)) and bool(re.search(r"value=\"whitelist\"", page)))

store.close() if hasattr(store, 'close') else None
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
