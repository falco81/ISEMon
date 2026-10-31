#!/usr/bin/python3 -I
"""isemon_web.py - the parts of the web server and the firewall that need
root, put in place by root (isemon 1.10.222; after otp's otp_web.py).

The things Settings may ask for that the daemon - which runs as `isemon`
and may not write a byte of /etc - cannot do itself:

  * who may reach which page: the dashboard, the published ban list
    (banfeed.php) and the health check (healthz.php), each as its own list
    of addresses and networks in /etc/nginx/conf.d/isemon.conf;
  * TLS: the certificate (with its chain, and the root it is checked
    against), the protocols, the ciphers, the DH parameters and HSTS;
  * the machine's firewall: a chain of isemon's own, ISEMON-IN, first in
    INPUT, for IPv4 and IPv6 - what isemon needs let in by itself, and the
    rules of the site's own;
  * this machine's network (1.10.228): its address, gateway, DNS, IPv6 and
    host name in NetworkManager and /etc/hosts, and a restart or a power-off
    (asked in net.ask, answered in net.json).

The daemon lays a request down in /var/lib/isemon/web/request.json and
systemd (isemon-web.path) starts this as root (isemon-web.service). Nothing
in the request is trusted: every value is checked against the one shape it
may have before it goes into a file, certificates and keys are read by
openssl and the key must be the certificate's own, nginx is asked (nginx -t)
before it is reloaded and every file is put back as it was when it says no,
a firewall file is checked with iptables-restore --test first, and the
folder is used through one descriptor, never a path the isemon account
could swap for a link.

What is there now - the certificate nginx answers with, the lists, the
firewall's own lines, the ports rsyslog listens on - is written to
look.json when the daemon asks with look.ask; nothing is changed for it.

The clock (1.10.228): asked in ntp.ask, answered in ntp.json - how chrony
sees it, a step to the right time now, and the time servers and time zone
put into /etc/chrony.conf when isemon is to set them (see ntp_part).

Root's SSH keys (1.10.239): asked in sshkeys.ask, answered in sshkeys.json -
the keys in /root/.ssh/authorized_keys, one added or taken away, and what
sshd makes of root (see sshkeys_part).

The updates of the operating system (1.10.239): asked in osup.ask, answered
in osup.ans - a look for updates or the update itself, started as a unit of
its own (isemon_web.py --os-job ID check|upgrade) that writes how far it is
into osup.json (see osup_part).

  isemon_web.py            serve request.json, look.ask, net.ask, ntp.ask, sshkeys.ask,
                           osup.ask and otptls.ask (as root, from systemd)
The otp logs over TLS (1.10.245): asked in otptls.ask, answered in
otptls.json - rsyslog's encrypted input for otp's nodes, its certificate and
key in /etc/pki/rsyslog/otp/ and /etc/rsyslog.d/10-otp-tls.conf, beside the
plain input, which is never touched (see otptls_part).

  isemon_web.py --os-job ID check|upgrade
                           a look for updates or the update (started by osup.ask)
  isemon_web.py --status   what is in place here (JSON)
"""
import ipaddress
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time

STATE_DIR = os.environ.get('ISEMON_STATE', '/var/lib/isemon')
NGINX_MAIN = os.environ.get('ISEMON_NGINX_CONF', '/etc/nginx/conf.d/isemon.conf')
CERT_DIR = os.environ.get('ISEMON_CERT_DIR', '/etc/nginx/certs')
RSYSLOG_FILES = os.environ.get('ISEMON_RSYSLOG', '/etc/rsyslog.conf:/etc/rsyslog.d')
NO_SERVICES = bool(os.environ.get('ISEMON_WEB_NO_SERVICES'))     # tests: no systemctl, nginx -t
SERVICE_GROUP = os.environ.get('ISEMON_GROUP', 'isemon')
LOOK_ASK = 'look.ask'
LOOK_FILE = 'look.json'

ADDR_RE = re.compile(r'^[0-9A-Fa-f:.]+(/[0-9]{1,3})?$')


class Refused(Exception):
    pass


def plain(text, how):
    """An address or a network - and nothing else: ipaddress keeps an IPv6
    scope id (fe80::1%eth0) with any character in it, newlines and braces
    included, and so into the nginx and iptables files root writes."""
    text = str(text or '').strip()
    if not ADDR_RE.match(text):
        raise ValueError('not a plain address')
    got = {'address': ipaddress.ip_address,
           'network': lambda t: ipaddress.ip_network(t, strict=False)}[how](text)
    if '%' in str(got):
        raise ValueError('a scope id is not taken')
    return got


# ---- the folder the isemon account owns: one descriptor, never a path ------------
FD = [None]


def web_fd():
    if FD[0] is None:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        top = os.open(STATE_DIR, flags)
        try:
            FD[0] = os.open('web', flags, dir_fd=top)
        finally:
            os.close(top)
    return FD[0]


def read_req(name, most=1048576):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=web_fd())
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise Refused('%s is not a file' % name)
        data = os.read(fd, most + 1)
    finally:
        os.close(fd)
    if len(data) > most:
        raise Refused('the request is far bigger than anything it may hold')
    return data


def write_here(name, text):
    """A file in the isemon account's folder: made beside and renamed over,
    so a link put there in its place is replaced, never followed."""
    d = web_fd()
    tmp = '.%s.%d' % (name, os.getpid())
    try:
        os.unlink(tmp, dir_fd=d)
    except OSError:
        pass
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640, dir_fd=d)
    with os.fdopen(fd, 'w') as f:
        f.write(text)
        try:
            import grp
            os.fchown(f.fileno(), 0, grp.getgrnam(SERVICE_GROUP).gr_gid)
        except (KeyError, OSError):
            pass
    os.replace(tmp, name, src_dir_fd=d, dst_dir_fd=d)


def write_root(path, text, mode):
    """A file of root's, replaced whole."""
    folder = os.path.dirname(path)
    os.makedirs(folder, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.isemon-', dir=folder)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', errors='surrogateescape') as f:
            f.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    if shutil.which('restorecon') and not NO_SERVICES:
        subprocess.run(['restorecon', path], capture_output=True)


# ---- what a request may hold ------------------------------------------------------
CERT_RE = re.compile(r'^(\s*-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----)+\s*$')
KEY_RE = re.compile(r'^\s*-----BEGIN (RSA |EC )?PRIVATE KEY-----[A-Za-z0-9+/=\s:,-]+'
                    r'-----END (RSA |EC )?PRIVATE KEY-----\s*$')
PROTOCOLS = ('TLSv1.2', 'TLSv1.3')
DH_CHOICES = ('none', 'ffdhe2048', 'ffdhe3072', 'ffdhe4096', 'gen2048', 'gen3072', 'gen4096')


def openssl(args, what, data=None):
    got = subprocess.run(['openssl'] + args, capture_output=True, text=True, input=data)
    if got.returncode != 0:
        raise Refused('%s: %s' % (what, ((got.stderr or got.stdout).strip().splitlines()[-1:]
                                         or ['openssl said no'])[0]))
    return got.stdout


def pem_set(cert, key, chain='', root=''):
    """A certificate, its key, the certificates between it and the root, and
    the root - each read by openssl, the key the certificate's own."""
    cert, key = str(cert or '').strip(), str(key or '').strip()
    chain, root = str(chain or '').strip(), str(root or '').strip()
    if not cert and not key:
        return None
    if not cert or not key:
        raise Refused('a certificate needs its key, and a key its certificate')
    for what, text in (('the certificate', cert), ('the chain', chain), ('the root', root)):
        if text and not CERT_RE.match(text):
            raise Refused('%s is not PEM (-----BEGIN CERTIFICATE-----)' % what)
    if not KEY_RE.match(key):
        raise Refused('the key is not a PEM private key without a passphrase')
    with tempfile.TemporaryDirectory(prefix='isemon-web-') as t:
        cf, kf = os.path.join(t, 'c.pem'), os.path.join(t, 'k.pem')
        with open(cf, 'w') as f:
            f.write(cert + '\n')
        with open(kf, 'w') as f:
            f.write(key + '\n')
        os.chmod(kf, 0o600)
        a = openssl(['x509', '-in', cf, '-noout', '-pubkey'], 'the certificate')
        b = openssl(['pkey', '-in', kf, '-pubout'], 'the key')
        if a.strip() != b.strip():
            raise Refused('the key is not the one of this certificate')
    return {'cert': cert + '\n', 'key': key + '\n', 'chain': (chain + '\n') if chain else '',
            'root': (root + '\n') if root else ''}


def tls_checked(t):
    if t is None:
        return None
    if not isinstance(t, dict):
        raise Refused('the TLS is not an object')
    out = {'pem': pem_set(t.get('cert'), t.get('key'), t.get('chain'), t.get('root'))}
    prot = t.get('protocols') or list(PROTOCOLS)
    if not isinstance(prot, list) or not prot or any(p not in PROTOCOLS for p in prot):
        raise Refused('the protocols are TLSv1.2 and/or TLSv1.3')
    out['protocols'] = [p for p in PROTOCOLS if p in prot]
    ciphers = str(t.get('ciphers') or '').strip()
    if ciphers:
        # Never starting with a dash: it goes to `openssl ciphers` as an
        # argument, and must not be read as an option.
        if not re.match(r'^[A-Za-z0-9_+!@][A-Za-z0-9_+!@=:.-]{0,1999}$', ciphers):
            raise Refused('the ciphers are an OpenSSL cipher list: letters, digits, : + ! - =')
        openssl(['ciphers', ciphers], 'OpenSSL does not know that cipher list')
    out['ciphers'] = ciphers
    out['prefer'] = bool(t.get('prefer'))
    dh = str(t.get('dh') or 'none')
    if dh not in DH_CHOICES:
        raise Refused('the DH parameters are one of %s' % ', '.join(DH_CHOICES))
    out['dh'] = dh
    try:
        out['hsts'] = int(t.get('hsts') or 0)
    except (TypeError, ValueError):
        raise Refused('HSTS is a number of seconds')
    if not 0 <= out['hsts'] <= 63072000:
        raise Refused('HSTS is 0 to 63072000 seconds')
    return out


def checked(r):
    """The request, every value in the one shape it may have."""
    if not isinstance(r, dict):
        raise Refused('the request is not an object')
    out = {'id': re.sub(r'[^A-Za-z0-9]', '', str(r.get('id') or ''))[:32],
           'hash': re.sub(r'[^0-9a-f]', '', str(r.get('hash') or ''))[:64]}
    out['tls'] = tls_checked(r.get('tls'))
    fw = r.get('fw')
    if isinstance(fw, dict):
        rules = fw.get('rules') or []
        if not isinstance(rules, list) or len(rules) > 2000:
            raise Refused('the firewall rules are a list, 2000 at most')
        out['fw'] = {'on': bool(fw.get('on')), 'rules': [fw_rule_checked(x) for x in rules]}
    else:
        out['fw'] = None
    out['access'] = access_checked(r.get('access'))
    # Automatic certificates by HTTP-01 (1.10.251): the names port 80
    # answers the ACME CA for - DNS names and nothing else, for they go into
    # server_name.
    names = r.get('acme')
    if names is None:
        out['acme'] = None
    else:
        if not isinstance(names, list) or len(names) > 10 or \
                not all(isinstance(n, str) and ACME_NAME_RE.match(n) for n in names):
            raise Refused('the names of the ACME certificate are DNS names, 10 at most')
        out['acme'] = [n.lower() for n in names]
    return out


ACME_NAME_RE = re.compile(r'^(?=.{1,253}\Z)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+'
                          r'[A-Za-z]{2,63}\Z')


# ---- nginx: finding things in a file somebody else may have written ------------
def server_block(text):
    """(start, end) of the HTTPS server { } of an nginx file."""
    i = 0
    while True:
        m = re.search(r'(?m)^[ \t]*server[ \t]*\{', text[i:])
        if not m:
            return None
        start = i + m.start()
        depth, j = 0, i + m.end() - 1
        while j < len(text):
            if text[j] == '{':
                depth += 1
            elif text[j] == '}':
                depth -= 1
                if depth == 0:
                    break
            j += 1
        block = text[start:j + 1]
        if re.search(r'(?m)^\s*listen\s+[^;]*443[^;]*ssl', block) or \
                re.search(r'(?m)^\s*ssl_certificate\s', block):
            return start, j + 1
        i = j + 1


def set_directive(block, name, value):
    """`name value;` in a server { } - replaced where it is, put in after
    server_name where it is not, taken out for None. Only the server's own
    lines: a location { } inside is left alone."""
    lines = block.split('\n')
    depth, at, insert_at = 0, [], None
    for n, line in enumerate(lines):
        if depth == 1 and re.match(r'^\s*%s\s' % re.escape(name), line):
            at.append(n)
        if depth == 1 and insert_at is None and re.match(r'^\s*server_name\s', line):
            insert_at = n + 1
        depth += line.count('{') - line.count('}')
    if value is None:
        for n in reversed(at):
            del lines[n]
        return '\n'.join(lines)
    text = '    %-25s %s;' % (name, value)
    if at:
        lines[at[0]] = text
        for n in reversed(at[1:]):
            del lines[n]
    else:
        lines.insert(insert_at if insert_at is not None else 1, text)
    return '\n'.join(lines)


def directive_now(block, name):
    """The value of `name` among the server's own lines, or ''."""
    depth = 0
    for line in block.split('\n'):
        if depth == 1:
            m = re.match(r'^\s*%s\s+([^;]*);' % re.escape(name), line)
            if m:
                return m.group(1).strip()
        depth += line.count('{') - line.count('}')
    return ''


CIPHERS_DEFAULT = ('ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:'
                   'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:'
                   'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305')

PROGRESS = {'step': 0, 'total': 5, 'id': ''}
DH_EXPECT_S = {'gen2048': 15, 'gen3072': 120, 'gen4096': 600}


def progress(words, step=None, expect=None):
    if step is not None:
        PROGRESS['step'] = step
    try:
        write_here('progress.json', json.dumps({
            'id': PROGRESS['id'], 'step': PROGRESS['step'], 'total': PROGRESS['total'],
            'words': words, 'at': time.time(), 'expect_s': expect}))
    except OSError:
        pass


TLS_FILES = {'cert': os.path.join(CERT_DIR, 'isemon.pem'),
             'key': os.path.join(CERT_DIR, 'isemon.key'),
             'root': os.path.join(CERT_DIR, 'isemon-ca.pem'),
             'dh': os.path.join(CERT_DIR, 'isemon-dh.pem')}


def dh_file(choice, path, had):
    """The DH parameters for `choice` in `path`: a group of RFC 7919, or made
    here (which takes a while - 4096 bits minutes). Made ones are made once."""
    if choice == 'none':
        return None
    # What is in the file is said by a file of root's beside it, not by
    # status.json, which lies in the isemon account's folder.
    try:
        with open(path + '.choice') as f:
            had = f.read().strip()
    except OSError:
        had = ''
    if choice == had and os.path.exists(path):
        return path
    if choice.startswith('ffdhe'):
        pem = openssl(['genpkey', '-genparam', '-algorithm', 'DH', '-pkeyopt',
                       'group:%s' % choice], 'the DH group %s' % choice)
    else:
        progress('making DH parameters of %s bits' % choice[3:], 2, DH_EXPECT_S.get(choice))
        pem = openssl(['dhparam', choice[3:]], 'making DH parameters of %s bits' % choice[3:])
    write_root(path, pem, 0o644)
    write_root(path + '.choice', choice + '\n', 0o644)
    return path


def tls_into(block, t, dh_path):
    """The server { } with the TLS of `t`: its files written, its lines set."""
    said = []
    progress('writing the certificate and the TLS settings', 3)
    if t['pem']:
        # The pair install.sh made (or the site put there) kept once, beside,
        # the first time this replaces it: there is always a way back.
        for k in ('cert', 'key'):
            keep = TLS_FILES[k] + '.before-isemon'
            if os.path.exists(TLS_FILES[k]) and not os.path.exists(keep):
                shutil.copy2(TLS_FILES[k], keep)
        write_root(TLS_FILES['cert'], t['pem']['cert'] + t['pem']['chain'], 0o644)
        write_root(TLS_FILES['key'], t['pem']['key'], 0o600)
        block = set_directive(block, 'ssl_certificate', TLS_FILES['cert'])
        block = set_directive(block, 'ssl_certificate_key', TLS_FILES['key'])
        if t['pem']['root']:
            write_root(TLS_FILES['root'], t['pem']['root'] + t['pem']['chain'], 0o644)
            block = set_directive(block, 'ssl_trusted_certificate', TLS_FILES['root'])
        else:
            block = set_directive(block, 'ssl_trusted_certificate', None)
        subj = openssl(['x509', '-noout', '-subject', '-enddate'], 'the certificate',
                       t['pem']['cert']).strip().replace('\n', ', ')
        said.append('certificate: %s' % subj)
    block = set_directive(block, 'ssl_protocols', ' '.join(t['protocols']))
    block = set_directive(block, 'ssl_ciphers', t['ciphers'] or CIPHERS_DEFAULT)
    block = set_directive(block, 'ssl_prefer_server_ciphers', 'on' if t['prefer'] else 'off')
    block = set_directive(block, 'ssl_dhparam', dh_path)
    if t['hsts']:
        block = set_directive(block, 'add_header Strict-Transport-Security',
                              '"max-age=%d" always' % t['hsts'])
    else:
        block = set_directive(block, 'add_header Strict-Transport-Security', None)
    said.append('%s; %s; DH %s%s' % (' '.join(t['protocols']),
                                     'ciphers as set' if t['ciphers'] else 'the usual ciphers',
                                     t['dh'], '; HSTS %d s' % t['hsts'] if t['hsts'] else ''))
    return block, said


def snapshot(paths):
    got = {}
    for p in paths:
        try:
            with open(p, 'rb') as f:
                got[p] = (f.read(), os.stat(p).st_mode & 0o777)
        except FileNotFoundError:
            got[p] = None
    return got


def put_back(snap):
    for p, was in snap.items():
        if was is None:
            try:
                os.unlink(p)
            except OSError:
                pass
        else:
            fd, tmp = tempfile.mkstemp(dir=os.path.dirname(p))
            with os.fdopen(fd, 'wb') as f:
                f.write(was[0])
            os.chmod(tmp, was[1])
            os.replace(tmp, p)
            if shutil.which('restorecon') and not NO_SERVICES:
                subprocess.run(['restorecon', p], capture_output=True)


# ---- who may reach which page ---------------------------------------------------
# The dashboard's list is the HTTPS server's own allow lines; the ban feed
# and the health check each get a location of their own, with a list of its
# own, only when they are set to something other than "as the dashboard".
# Every list is between marks of isemon's, so it is found again after a
# hand edit; the machine itself (127.0.0.1, ::1) is always let in.
ALWAYS = ('127.0.0.1', '::1')
PAGES = (('banfeed', 'BANFEED', '/banfeed.php'), ('health', 'HEALTH', '/healthz.php'))


def nets_checked(one, what):
    nets = []
    for x in (one.get('from') or [])[:400]:
        try:
            net = plain(x, 'network')
        except ValueError:
            raise Refused('%r is not an address or a network' % str(x)[:60])
        # One address is written as the address, not as a network of one -
        # a /32 of IPv4 or a /128 of IPv6, never an IPv6 /32.
        nets.append(str(net.network_address) if net.prefixlen == net.max_prefixlen else str(net))
    return list(dict.fromkeys(n for n in nets if n not in ALWAYS))


def access_checked(a):
    if not isinstance(a, dict):
        return None
    out = {}
    d = a.get('dashboard')
    if not isinstance(d, dict):
        raise Refused('who may reach the dashboard is not given')
    nets = nets_checked(d, 'the dashboard')
    if not d.get('any') and not nets:
        raise Refused('the dashboard would be for this machine alone: give a network or '
                      'everybody')
    out['dashboard'] = {'any': bool(d.get('any')), 'from': nets}
    for k, _mark, _loc in PAGES:
        one = a.get(k)
        if not isinstance(one, dict):
            one = {'same': True}
        if one.get('same'):
            out[k] = {'same': True}
            continue
        nets = nets_checked(one, k)
        if not one.get('any') and not nets:
            raise Refused('the %s page would be for this machine alone: give a network, '
                          'everybody, or "as the dashboard"' % k)
        out[k] = {'same': False, 'any': bool(one.get('any')), 'from': nets}
    return out


def access_lines(one, pad):
    if one.get('any'):
        return pad + 'allow all;                    # everybody (Settings - Firewall and access)'
    return '\n'.join('%sallow %s;' % (pad, n) for n in one['from'])


def dashboard_into(block, one):
    """The HTTPS server's own allow lines as asked: the marked list, then the
    machine itself, then deny all. The allow and deny lines that were there
    (install.sh's, or somebody's) are what the marks replace."""
    lines = block.split('\n')
    begin = [n for n, l in enumerate(lines) if l.strip() == '# DASHBOARD-ALLOW-BEGIN']
    end = [n for n, l in enumerate(lines) if l.strip() == '# DASHBOARD-ALLOW-END']
    want = ['    # DASHBOARD-ALLOW-BEGIN'] + access_lines(one, '    ').split('\n') + \
        ['    # DASHBOARD-ALLOW-END']
    if begin and end and begin[0] < end[0]:
        return '\n'.join(lines[:begin[0]] + want + lines[end[0] + 1:])
    # The server's own run of allow / deny lines (comments after them kept
    # out): replaced by the marked list and the three that always follow it.
    depth, run_at = 0, []
    for n, l in enumerate(lines):
        if depth == 1 and re.match(r'^\s*(allow|deny)\s+[^;]+;', l):
            if run_at and n != run_at[-1] + 1:
                break
            run_at.append(n)
        elif run_at and depth == 1 and l.strip() and not l.strip().startswith('#'):
            break
        depth += l.count('{') - l.count('}')
    tail = ['    allow 127.0.0.1;', '    allow ::1;', '    deny  all;']
    if run_at:
        return '\n'.join(lines[:run_at[0]] + want + tail + lines[run_at[-1] + 1:])
    at = next((n + 1 for n, l in enumerate(lines) if re.match(r'^\s*server_name\s', l)), 1)
    return '\n'.join(lines[:at] + want + tail + lines[at:])


def dashboard_now(block):
    """What the dashboard's list says now: (any, nets, marked)."""
    m = re.search(r'# DASHBOARD-ALLOW-BEGIN\n(.*?)\n[ \t]*# DASHBOARD-ALLOW-END', block, re.S)
    if m:
        nets = re.findall(r'(?m)^\s*allow\s+([^;\s]+);', m.group(1))
        return 'all' in nets, [n for n in nets if n != 'all'], True
    depth, nets, deny_all = 0, [], False
    for l in block.split('\n'):
        if depth == 1:
            a = re.match(r'^\s*allow\s+([^;\s]+);', l)
            if a:
                nets.append(a.group(1))
            if re.match(r'^\s*deny\s+all\s*;', l):
                deny_all = True
        depth += l.count('{') - l.count('}')
    rest = [n for n in nets if n not in ALWAYS and n != 'all']
    return ('all' in nets) or not deny_all, rest, False


def php_lines(block):
    """The lines a location of its own needs to hand its file to PHP: those
    of the server's `location ~ \\.php$`, as the site wrote them."""
    m = re.search(r'(?ms)^[ \t]*location\s+~\*?\s+\\\.php\$\s*\{(.*?)^[ \t]*\}', block)
    if not m:
        m = re.search(r'(?ms)^[ \t]*location\s+=\s+/index\.php\s*\{(.*?)^[ \t]*\}', block)
    if not m:
        raise Refused('no location handing .php to PHP was found in %s' % NGINX_MAIN)
    keep = []
    for l in m.group(1).split('\n'):
        s = l.strip()
        if re.match(r'^(fastcgi_|include\s)', s):
            s = re.sub(r'\$document_root/index\.php', '$document_root$fastcgi_script_name', s)
            keep.append('        ' + s)
    if not any('fastcgi_pass' in l for l in keep):
        raise Refused('the .php location in %s has no fastcgi_pass' % NGINX_MAIN)
    return keep


def page_into(block, key, mark, loc, one):
    """A location of its own for the ban feed or the health check, with a
    list of its own - or none (as the dashboard)."""
    begin, end = '    # isemon-%s-begin' % key, '    # isemon-%s-end' % key
    # Taken out whole, with the blank line put in after it, wherever it is.
    rx = re.compile(r'(?ms)^[ \t]*# isemon-%s-begin[^\n]*\n.*?^[ \t]*# isemon-%s-end[^\n]*\n'
                    r'(?:[ \t]*\n)?' % (key, key))
    block = rx.sub('', block)
    if one.get('same'):
        return block
    body = ([begin + ' (Settings - Firewall and access: who may reach %s)' % loc,
             '    location = %s {' % loc,
             '        # %s-ALLOW-BEGIN' % mark] + access_lines(one, '        ').split('\n') +
            ['        # %s-ALLOW-END' % mark, '        allow 127.0.0.1;', '        allow ::1;',
             '        deny  all;'] + php_lines(block) + ['    }', end])
    # Before the catch-all .php location, or at the end of the server.
    m = re.search(r'(?m)^[ \t]*location\s+~\*?\s+\\\.php\$', block)
    at = m.start() if m else block.rstrip().rfind('}')
    return block[:at] + '\n'.join(body) + '\n\n' + block[at:]


def page_now(block, key, mark):
    m = re.search(r'# isemon-%s-begin.*?# %s-ALLOW-BEGIN\n(.*?)\n[ \t]*# %s-ALLOW-END'
                  % (key, mark, mark), block, re.S)
    if not m:
        return {'same': True}
    nets = re.findall(r'(?m)^\s*allow\s+([^;\s]+);', m.group(1))
    return {'same': False, 'any': 'all' in nets, 'from': [n for n in nets if n != 'all']}


def access_now():
    try:
        with open(NGINX_MAIN) as f:
            text = f.read()
    except OSError:
        return {}
    where = server_block(text)
    if not where:
        return {}
    block = text[where[0]:where[1]]
    anyone, nets, marked = dashboard_now(block)
    out = {'dashboard': {'any': anyone, 'from': nets, 'marked': marked}}
    for k, mark, _loc in PAGES:
        out[k] = page_now(block, k, mark)
    return out


def cert_now():
    """The certificate nginx answers with now, read off its file."""
    try:
        with open(NGINX_MAIN) as f:
            text = f.read()
    except OSError as e:
        return {'said': 'the vhost cannot be read: %s' % e}
    where = server_block(text)
    if not where:
        return {'said': 'no HTTPS server { } in %s' % NGINX_MAIN}
    block = text[where[0]:where[1]]
    out = {'path': directive_now(block, 'ssl_certificate'),
           'key_path': directive_now(block, 'ssl_certificate_key'),
           'protocols': directive_now(block, 'ssl_protocols'),
           'ciphers': directive_now(block, 'ssl_ciphers'),
           'dhparam': directive_now(block, 'ssl_dhparam'),
           'hsts': directive_now(block, 'add_header Strict-Transport-Security')}
    if out['path']:
        try:
            with open(out['path']) as f:
                pem = f.read(400000)
            # The certificates only: a site whose file holds the key as
            # well must not see it copied into the isemon account's folder.
            out['pem'] = ''.join(m.group(0) + '\n' for m in re.finditer(
                r'-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----', pem))
        except OSError as e:
            out['said'] = 'the certificate file cannot be read: %s' % e
    return out


# ---- port 80 for the ACME CA (1.10.251; after otp_web.py 1.0.169) -------------------
# The port-80 server sends /.well-known/acme-challenge/ to acme.php, which asks
# the daemon for the answer kept in the database; everything else goes on to
# HTTPS as before. The location is let in for everybody - the CA asks from
# wherever it is - and the names the certificate is ordered for go into its
# server_name. Between marks of isemon's, so it is found again; the
# redirect of the server itself is moved into `location /`, for a `return`
# of the server's own is done before any location is looked at.
ACME_BEGIN = '    # isemon-acme-begin (Settings - Automatic certificates)'
ACME_END = '    # isemon-acme-end'


def http_block(text):
    """(start, end) of the port-80 server { } of an nginx file."""
    for m in re.finditer(r'(?m)^[ \t]*server[ \t]*\{', text):
        depth, j = 0, m.end() - 1
        while j < len(text):
            if text[j] == '{':
                depth += 1
            elif text[j] == '}':
                depth -= 1
                if depth == 0:
                    break
            j += 1
        block = text[m.start():j + 1]
        if re.search(r'(?m)^\s*listen\s+(\[::\]:)?80\b', block) and \
                not re.search(r'(?m)^\s*listen\s+[^;]*\bssl\b', block):
            return m.start(), j + 1
    return None


def acme_location(https_block, main):
    """The location, its PHP as the HTTPS server's own .php location hands
    files to PHP (the socket the site uses), the file under its root."""
    root = directive_now(https_block, 'root') or '/var/www/isemon'
    if not re.match(r'^/[A-Za-z0-9._/-]{1,200}$', root):
        raise Refused('the root of the HTTPS server is not a plain path: %r' % root[:80])
    php = [l for l in php_lines(https_block)
           if not re.match(r'^\s*fastcgi_param\s+(SCRIPT_FILENAME|HTTPS)\s', l)
           and not re.match(r'^\s*fastcgi_(index|read_timeout|send_timeout)\s', l)]
    lines = [ACME_BEGIN,
             '    # The CA\'s HTTP-01 question, answered by acme.php from what the daemon',
             '    # keeps; for everybody - whoever else the pages are for.',
             '    location ^~ /.well-known/acme-challenge/ {',
             '        allow all;']
    if 'zone=isemon_all:' in main:
        lines.append('        limit_req zone=isemon_all burst=20 nodelay;')
    lines += php
    lines += ['        fastcgi_param  SCRIPT_FILENAME %s/acme.php;' % root.rstrip('/'),
              '        fastcgi_read_timeout 10s;', '    }', ACME_END]
    return lines


def acme_into(main, names):
    """The port-80 server given the location for the CA and the names in its
    server_name. The file as it was when there is no port-80 server."""
    where = http_block(main)
    https = server_block(main)
    if not where or not https:
        return main, 'nginx: no port-80 server { } in %s - the CA cannot be answered on port ' \
                     '80 (put one in, or use DNS-01)' % NGINX_MAIN
    block = main[where[0]:where[1]]
    lines = block.split('\n')
    # What was put in before, taken out whole.
    begin = [n for n, l in enumerate(lines) if l.strip().startswith('# isemon-acme-begin')]
    end = [n for n, l in enumerate(lines) if l.strip() == '# isemon-acme-end']
    if begin and end and begin[0] < end[-1]:
        del lines[begin[0]:end[-1] + 1]
    # A `return` of the server's own (the redirect to HTTPS) into location /.
    depth, out = 0, []
    for l in lines:
        if depth == 1 and re.match(r'^\s*return\s+[^;]+;\s*(#.*)?$', l):
            out += ['    location / {', '    ' + l.rstrip(), '    }']
        else:
            out.append(l)
        depth += l.count('{') - l.count('}')
    lines = out
    # The location after server_name (or after the first line).
    at = next((n + 1 for n, l in enumerate(lines) if re.match(r'^\s*server_name\s', l)), 1)
    lines[at:at] = acme_location(main[https[0]:https[1]], main)
    new = '\n'.join(lines)
    m = re.search(r'(?m)^(\s*server_name\s+)([^;#]*);', new)
    if m and names:
        have = m.group(2).split()
        want = have + [n for n in names if n not in have]
        if want != have:
            new = new[:m.start()] + m.group(1) + ' '.join(want) + ';' + new[m.end():]
    if new == block:
        return main, ''
    return main[:where[0]] + new + main[where[1]:], \
        'nginx: port 80 answers the ACME CA (%s)' % (', '.join(names) or 'no name yet')


def nginx_part(r, last):
    """The server's TLS and lists, as asked. Returns (words, dh made)."""
    said, dh = [], (last.get('dh') or 'none')
    t = r['tls']
    dh_path = None
    # The DH files as they were, so that a change refused below puts them
    # back too, and so that new parameters are known to be new (1.10.227):
    # the file keeps its name, so nginx's lines did not change, nothing was
    # reloaded, and nginx went on with the old group until something else
    # reloaded it.
    dh_snap = snapshot([TLS_FILES['dh'], TLS_FILES['dh'] + '.choice'])
    if t:
        # DH parameters made first: it can take minutes, and nginx's file is
        # read only after it, so nothing changed in it meanwhile is written
        # over with an older copy.
        dh_path = dh_file(t['dh'], TLS_FILES['dh'], last.get('dh'))
        dh = t['dh']
    dh_new = snapshot(list(dh_snap)) != dh_snap
    paths = [NGINX_MAIN] + list(TLS_FILES.values())
    snap = snapshot(paths)
    snap.update(dh_snap)
    changed = False
    try:
        try:
            with open(NGINX_MAIN) as f:
                main = f.read()
        except OSError as e:
            raise Refused('the dashboard\'s nginx file cannot be read (%s): %s' % (NGINX_MAIN, e))
        if r.get('acme') is not None:
            new_main, words = acme_into(main, r['acme'])
            if words:
                said.append(words)
            if new_main != main:
                write_root(NGINX_MAIN, new_main, 0o644)
                main, changed = new_main, True
        where = server_block(main)
        if not where:
            raise Refused('no HTTPS server { } was found in %s' % NGINX_MAIN)
        block = main[where[0]:where[1]]
        new = block
        if r.get('access'):
            a = r['access']
            new = dashboard_into(new, a['dashboard'])
            for k, mark, loc in PAGES:
                new = page_into(new, k, mark, loc, a[k])
            if new != block:
                said.append('nginx: who may reach the dashboard, the ban feed and the health '
                            'check set')
        if t:
            new, words = tls_into(new, t, dh_path)
            said += words
        if new != block:
            write_root(NGINX_MAIN, main[:where[0]] + new + main[where[1]:], 0o644)
            changed = True
        elif t and (t['pem'] or (dh_new and dh_path)):
            changed = True          # the same lines, new files: nginx reads them again
        if changed and not NO_SERVICES:
            progress('asking nginx, and reloading it', 4)
            got = subprocess.run(['nginx', '-t'], capture_output=True, text=True)
            if got.returncode != 0:
                raise Refused('nginx does not take it, so it is as it was: %s'
                              % ((got.stderr or '').strip().splitlines() or ['?'])[-1][:300])
            got = subprocess.run(['systemctl', 'reload', 'nginx'], capture_output=True,
                                 text=True)
            if got.returncode != 0:
                # Said, not claimed (1.10.234): a reload that failed left
                # nginx answering with what it had, and the page said reloaded.
                raise Refused('nginx took it, but did not reload: %s'
                              % ((got.stderr or '').strip().splitlines() or ['?'])[-1][:300])
            said.append('nginx reloaded')
    except BaseException:
        put_back(snap)
        raise
    return said, dh


# ---- the machine's firewall ------------------------------------------------------
# Everything isemon opens is in a chain of its own, ISEMON-IN, jumped to first
# from INPUT - for IPv4 (iptables) and IPv6 (ip6tables). The rules already on
# the machine are left exactly as they are: isemon's chain only adds to them.
# With iptables-services the chain is also written into /etc/sysconfig/iptables
# and ip6tables (between marks of its own, the rest of the file untouched,
# its comments kept), so it is there after a reboot.
FW_CHAIN = 'ISEMON-IN'
FW_FILES = {4: os.environ.get('ISEMON_FW_FILE4', '/etc/sysconfig/iptables'),
            6: os.environ.get('ISEMON_FW_FILE6', '/etc/sysconfig/ip6tables')}
FW_TOOLS = {4: ('iptables', 'iptables-restore', 'iptables-save'),
            6: ('ip6tables', 'ip6tables-restore', 'ip6tables-save')}
FW_PROTOS = ('tcp', 'udp', 'icmp', 'any')
FW_MARK = '# isemon:'


def fw_backend():
    if not NO_SERVICES and shutil.which('firewall-cmd') and \
            subprocess.run(['firewall-cmd', '--state'], capture_output=True).returncode == 0:
        return 'firewalld'
    if shutil.which('iptables'):
        return 'iptables'
    return ''


def fw_rule_checked(x):
    if not isinstance(x, dict):
        raise Refused('a firewall rule is not an object')
    try:
        fam = int(x.get('family') or 0)
    except (TypeError, ValueError):
        fam = 0
    if fam not in (4, 6):
        raise Refused('a firewall rule is for IPv4 or IPv6')
    proto = str(x.get('proto') or 'any')
    if proto not in FW_PROTOS:
        raise Refused('the protocol is one of %s' % ', '.join(FW_PROTOS))
    port = str(x.get('port') or '').replace(' ', '')
    if port:
        if proto not in ('tcp', 'udp'):
            raise Refused('a port is for TCP or UDP')
        parts = port.split(',')
        # A range counts as two, as iptables counts it; matched whole.
        if sum(2 if '-' in p else 1 for p in parts) > 15 or \
                not all(re.fullmatch(r'[0-9]{1,5}(-[0-9]{1,5})?', p) for p in parts):
            raise Refused('the ports are numbers or ranges, by commas: 80,443 or 6514-6515')
        for p in parts:
            a, _, b = p.partition('-')
            if not 1 <= int(a) <= 65535 or (b and not int(a) <= int(b) <= 65535):
                raise Refused('%s is not a port or a range of them' % p)
    src = str(x.get('source') or '').strip()
    if src:
        try:
            net = plain(src, 'network')
        except ValueError:
            raise Refused('%r is not an address or a network' % src[:60])
        if net.version != fam:
            raise Refused('%s is not an IPv%d address' % (src, fam))
        src = str(net)
    action = str(x.get('action') or 'accept')
    if action not in ('accept', 'drop', 'reject'):
        raise Refused('a rule accepts, drops or rejects')
    note = re.sub(r'[^A-Za-z0-9 ._:/@()+,-]', '', str(x.get('note') or ''))[:120]
    return {'family': fam, 'proto': proto, 'port': port, 'source': src, 'action': action,
            'note': note}


def fw_args(r):
    a = ['-A', FW_CHAIN]
    if r['source']:
        a += ['-s', r['source']]
    if r['proto'] != 'any':
        proto = 'ipv6-icmp' if (r['proto'] == 'icmp' and r['family'] == 6) else r['proto']
        a += ['-p', proto]
    if r['port']:
        if ',' in r['port']:
            a += ['-m', 'multiport', '--dports', r['port'].replace('-', ':')]
        else:
            a += ['--dport', r['port'].replace('-', ':')]
    a += ['-m', 'comment', '--comment', '"isemon: %s"' % (r['note'] or r['proto'])]
    a += ['-j', r['action'].upper()]
    return ' '.join(a)


def fw_strip(text):
    """A saved ruleset without anything isemon put in it."""
    out = []
    for line in text.split('\n'):
        # iptables-save -c puts the counters first: [12:3456] -A INPUT ...
        k = re.sub(r'^\[\d+:\d+\]\s+', '', line.strip())
        if k.startswith(FW_MARK) or re.match(r'^:%s - \[\d+:\d+\]$' % FW_CHAIN, k) or \
                k == '-A INPUT -j %s' % FW_CHAIN or k.startswith('-A %s ' % FW_CHAIN):
            continue
        out.append(line)
    return '\n'.join(out)


def fw_into(text, lines, on):
    """isemon's chain into a saved ruleset (iptables-services' file), in the
    *filter table: its name, the jump from INPUT first, its rules last."""
    text = fw_strip(text)
    if not on:
        return text
    rows = text.split('\n')
    try:
        start = next(i for i, l in enumerate(rows) if l.strip() == '*filter')
    except StopIteration:
        rows += ['*filter', ':INPUT ACCEPT [0:0]', ':FORWARD ACCEPT [0:0]',
                 ':OUTPUT ACCEPT [0:0]', 'COMMIT']
        start = len(rows) - 5
    end = next((i for i in range(start + 1, len(rows)) if rows[i].strip() == 'COMMIT'), None)
    if end is None:
        raise Refused('the saved firewall has a *filter table without COMMIT')
    first_input = next((i for i in range(start, end) if rows[i].startswith('-A INPUT')), end)
    # The last declaration BEFORE the first rule of INPUT (1.10.238): one of
    # a hand-written file that came after it had the rows between written
    # twice.
    last_decl = max([i for i in range(start, first_input) if rows[i].startswith(':')] or [start])
    block = ['%s isemon opens what its functions need here (Settings - Firewall and access); '
             'changed only there' % FW_MARK] + lines + ['%s end' % FW_MARK]
    rows = (rows[:last_decl + 1] + [':%s - [0:0]' % FW_CHAIN] +
            rows[last_decl + 1:first_input] +
            ['%s every rule isemon makes is in %s' % (FW_MARK, FW_CHAIN),
             '-A INPUT -j %s' % FW_CHAIN] +
            rows[first_input:end] + block + rows[end:])
    return '\n'.join(rows)


def fw_now(fam):
    """What the machine's INPUT holds now, isemon's chain apart - shown on
    the page as what else is in the firewall."""
    tool = FW_TOOLS[fam][2]
    if not shutil.which(tool) or NO_SERVICES:
        return []
    got = subprocess.run([tool, '-t', 'filter'], capture_output=True, text=True)
    out = []
    for line in got.stdout.split('\n'):
        # The jump to isemon's chain shown too (1.10.223): where it stands
        # in INPUT is the one thing about INPUT isemon decides.
        if line.startswith(':INPUT ') or line.startswith('-A INPUT'):
            out.append(line.strip())
    return out[:200]


def fw_chain_now(fam):
    """isemon's own chain, as the kernel holds it now."""
    tool = FW_TOOLS[fam][0]
    if not shutil.which(tool) or NO_SERVICES:
        return []
    got = subprocess.run([tool, '-S', FW_CHAIN], capture_output=True, text=True)
    return [l.strip() for l in got.stdout.split('\n') if l.strip()][:400] \
        if got.returncode == 0 else []


def fw_base(fam):
    """What the chain lets through before anybody's rule: the machine's own
    loopback, the answers to what it asked itself (the router, the directory,
    DNS, the public lists), and on IPv6 the neighbour discovery it cannot
    live without. Ahead of the rules, so a DROP of somebody's cannot shut
    any of them out."""
    out = ['-A %s -i lo -m comment --comment "isemon: loopback" -j ACCEPT' % FW_CHAIN,
           '-A %s -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment '
           '"isemon: answers" -j ACCEPT' % FW_CHAIN]
    if fam == 6:
        out += ['-A %s -p ipv6-icmp -m icmp6 --icmpv6-type %d -m comment --comment '
                '"isemon: neighbour discovery" -j ACCEPT' % (FW_CHAIN, t)
                for t in (133, 134, 135, 136)]
    return out


def fw_said(stderr):
    """What iptables said, without its last line: that is always the hint
    to read its help."""
    lines = [x.strip() for x in (stderr or '').strip().splitlines()
             if x.strip() and not x.strip().startswith('Try `')]
    return '; '.join(lines[-3:]) or '?'


def fw_apply(f, said):
    for fam in (4, 6):
        tool, restore, _save = FW_TOOLS[fam]
        lines = fw_base(fam) + [fw_args(r) for r in f['rules'] if r['family'] == fam]
        if not shutil.which(tool):
            continue
        if f['on']:
            snippet = '*filter\n:%s - [0:0]\n%s\nCOMMIT\n' % (FW_CHAIN, '\n'.join(lines))
            got = subprocess.run([restore, '--noflush'], input=snippet, capture_output=True,
                                 text=True)
            if got.returncode != 0:
                raise Refused('%s does not take the rules: %s' % (restore, fw_said(got.stderr)))
            if subprocess.run([tool, '-C', 'INPUT', '-j', FW_CHAIN],
                              capture_output=True).returncode != 0:
                subprocess.run([tool, '-I', 'INPUT', '1', '-j', FW_CHAIN], capture_output=True)
            said.append('IPv%d: %d rule(s) in %s' % (fam, len(lines), FW_CHAIN))
        else:
            while subprocess.run([tool, '-D', 'INPUT', '-j', FW_CHAIN],
                                 capture_output=True).returncode == 0:
                pass
            subprocess.run([tool, '-F', FW_CHAIN], capture_output=True)
            subprocess.run([tool, '-X', FW_CHAIN], capture_output=True)
        # Kept over a reboot, where iptables-services keeps the rules.
        path = FW_FILES[fam]
        if os.path.exists(path):
            with open(path) as fh:
                old = fh.read()
            new = fw_into(old, lines, f['on'])
            if new != old:
                fd, tmp = tempfile.mkstemp(prefix='.isemon-fw-', dir=os.path.dirname(path))
                with os.fdopen(fd, 'w') as fh:
                    fh.write(new if new.endswith('\n') else new + '\n')
                test = subprocess.run([restore, '--test', tmp], capture_output=True, text=True)
                if test.returncode != 0:
                    os.unlink(tmp)
                    raise Refused('%s would not take the file, so it was left as it was: %s' % (
                        restore, fw_said(test.stderr)))
                os.chmod(tmp, os.stat(path).st_mode & 0o777)
                os.replace(tmp, path)
                if shutil.which('restorecon') and not NO_SERVICES:
                    subprocess.run(['restorecon', path], capture_output=True)
                said.append('%s: kept over a reboot' % path)
        elif f['on']:
            said.append('IPv%d: not kept over a reboot - %s is not there (dnf install '
                        'iptables-services)' % (fam, path))


def fw_can(f):
    """Refused before anything is touched when the firewall asked for cannot
    be done here at all (1.10.227). Found out only after nginx had been
    changed and reloaded, the whole request was said to have failed while
    the new certificate and lists were already in force - and the same
    request was never asked again."""
    if f is None or not f['on']:
        return
    fw_part_check(fw_backend())


def fw_part_check(backend):
    if backend == 'firewalld':
        raise Refused('firewalld manages this machine\'s firewall: isemon leaves it to it. '
                      'To manage it here, use iptables (dnf install iptables-services; '
                      'systemctl disable --now firewalld; systemctl enable --now iptables '
                      'ip6tables)')
    if not backend:
        raise Refused('there is no iptables on this machine')


def fw_part(f):
    """The firewall as asked: (words, report)."""
    said = []
    backend = fw_backend()
    report = {'backend': backend}
    if f is None:
        return said, report
    if backend == 'firewalld':
        if f['on']:
            raise Refused('firewalld manages this machine\'s firewall: isemon leaves it to it. '
                          'To manage it here, use iptables (dnf install iptables-services; '
                          'systemctl disable --now firewalld; systemctl enable --now iptables '
                          'ip6tables)')
        return said, report
    if not backend:
        if f['on']:
            raise Refused('there is no iptables on this machine')
        return said, report
    progress('the firewall', 4)
    # As it was, live and in the files, to go back to when anything fails
    # half way - never a machine left half done.
    was_live, was_file = {}, {}
    for fam in (4, 6):
        if shutil.which(FW_TOOLS[fam][2]):
            was_live[fam] = subprocess.run([FW_TOOLS[fam][2]], capture_output=True,
                                           text=True).stdout
        if os.path.exists(FW_FILES[fam]):
            was_file[fam] = snapshot([FW_FILES[fam]])
    try:
        fw_apply(f, said)
    except BaseException:
        for fam, text in was_live.items():
            if text.strip():
                subprocess.run([FW_TOOLS[fam][1]], input=text, capture_output=True, text=True)
            else:
                tool = FW_TOOLS[fam][0]
                while subprocess.run([tool, '-D', 'INPUT', '-j', FW_CHAIN],
                                     capture_output=True).returncode == 0:
                    pass
                subprocess.run([tool, '-F', FW_CHAIN], capture_output=True)
                subprocess.run([tool, '-X', FW_CHAIN], capture_output=True)
        for snap in was_file.values():
            put_back(snap)
        raise
    if not f['on']:
        said.append('the firewall: isemon\'s rules taken away; the rest is as it was')
    return said, report


# ---- the ports the logs arrive on -------------------------------------------------
def rsyslog_ports():
    """What rsyslog on this machine listens on, read off its own files:
    [{'proto': 'udp'|'tcp', 'port': '514'}]. RELP and TLS are TCP."""
    files = []
    for one in RSYSLOG_FILES.split(':'):
        if os.path.isdir(one):
            files += sorted(os.path.join(one, n) for n in os.listdir(one) if n.endswith('.conf'))
        elif os.path.isfile(one):
            files.append(one)
    found = []
    for path in files:
        try:
            with open(path, encoding='utf-8', errors='replace') as f:
                text = f.read(1 << 20)
        except OSError:
            continue
        text = '\n'.join(l for l in text.split('\n') if not l.strip().startswith('#'))
        for m in re.finditer(r'input\s*\(([^)]*)\)', text, re.S):
            body = m.group(1)
            kind = re.search(r'type\s*=\s*"(im[a-z]+)"', body)
            port = re.search(r'port\s*=\s*"([0-9]{1,5})"', body)
            if kind and kind.group(1) in ('imudp', 'imtcp', 'imptcp', 'imrelp'):
                found.append({'proto': 'udp' if kind.group(1) == 'imudp' else 'tcp',
                              'port': port.group(1) if port else '514',
                              'file': os.path.basename(path)})
        for m in re.finditer(r'(?m)^\s*\$(UDPServerRun|InputTCPServerRun|InputRELPServerRun|'
                             r'InputPTCPServerRun)\s+([0-9]{1,5})', text):
            found.append({'proto': 'udp' if m.group(1) == 'UDPServerRun' else 'tcp',
                          'port': m.group(2), 'file': os.path.basename(path)})
    seen, out = set(), []
    for one in found:
        k = (one['proto'], one['port'])
        if k not in seen and 1 <= int(one['port']) <= 65535:
            seen.add(k)
            out.append(one)
    return out


def ssh_ports():
    """The ports sshd listens on, from its own file (22 when it does not say)."""
    ports = []
    for path in ['/etc/ssh/sshd_config'] + sorted(
            os.path.join('/etc/ssh/sshd_config.d', n)
            for n in (os.listdir('/etc/ssh/sshd_config.d')
                      if os.path.isdir('/etc/ssh/sshd_config.d') else [])
            if n.endswith('.conf')):
        try:
            with open(path, encoding='utf-8', errors='replace') as f:
                for line in f:
                    m = re.match(r'^\s*Port\s+([0-9]{1,5})\s*$', line, re.I)
                    if m:
                        ports.append(m.group(1))
        except OSError:
            pass
    return list(dict.fromkeys(ports)) or ['22']


def look():
    """Everything the page shows of how things are here, changing nothing."""
    out = {'at': time.time(), 'cert': cert_now(), 'access': access_now(),
           'backend': fw_backend(), 'rsyslog': rsyslog_ports(), 'ssh': ssh_ports(),
           'nginx_conf': NGINX_MAIN, 'files': {
               str(f): os.path.exists(p) for f, p in FW_FILES.items()}}
    if out['backend'] == 'iptables':
        out['now'] = {4: fw_now(4), 6: fw_now(6)}
        out['chain'] = {4: fw_chain_now(4), 6: fw_chain_now(6)}
    return out


def drop_entry(name):
    """An entry of the request folder taken away, whatever the isemon account
    made of it (1.10.238): a file, a link, an empty folder - or a folder with
    something in it, moved aside and never read. True when one was there."""
    d = web_fd()
    try:
        os.unlink(name, dir_fd=d)
        return True
    except FileNotFoundError:
        return False
    except OSError:
        pass
    try:
        os.rmdir(name, dir_fd=d)
        return True
    except OSError:
        pass
    try:
        os.rename(name, '.refused-%s-%d' % (name, int(time.time())), src_dir_fd=d, dst_dir_fd=d)
    except OSError:
        pass
    return True


def look_part():
    if not drop_entry(LOOK_ASK):
        return
    try:
        out = look()
    except Exception as e:                              # noqa: BLE001 - said, never lost
        out = {'at': time.time(), 'said': 'it could not be read: %s' % str(e)[:200]}
    write_here(LOOK_FILE, json.dumps(out))


# ---- the clock: chrony (1.10.228; after otp's otp_web.py 1.0.120) ----------------
# Asked in ntp.ask: how the clock is (read), chrony's servers set (apply), a
# step to the right time now (sync); answered in ntp.json. /etc/chrony.conf
# keeps everything of its own: when isemon sets the servers, the file's own
# server/pool/makestep/allow lines are commented out (#isemon# ) and isemon's
# block goes between two marks at the end - and they are put back as they
# were when isemon stops setting them. Nothing is changed for a read.
NTP_ASK = 'ntp.ask'
NTP_FILE = 'ntp.json'
CHRONYC = os.environ.get('ISEMON_CHRONYC', 'chronyc')
TIMEDATECTL = os.environ.get('ISEMON_TIMEDATECTL', 'timedatectl')
CHRONY_CONF = os.environ.get('ISEMON_CHRONY_CONF', '/etc/chrony.conf')
NTP_NO_SERVICE = bool(os.environ.get('ISEMON_NTP_NO_SERVICE'))  # tests: no systemctl, set-ntp
NTP_BEGIN = '# ---- isemon: the time servers, set on its pages (Settings - Time) ----'
NTP_END = '# ---- isemon: end ----'
NTP_OFF = '#isemon# '
NTP_KEYS = ('server', 'pool', 'peer', 'makestep', 'allow', 'minsources', 'maxdistance',
            'sourcedir')
NTP_NAME_RE = re.compile(r'^(?=.{1,253}\Z)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?'
                         r'(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\Z')
TZ_RE = re.compile(r'^[A-Za-z][A-Za-z0-9_+-]{0,39}(/[A-Za-z0-9_+-]{1,40}){0,3}\Z')


def ntp_run(cmd, what, ok=(0,), timeout=60):
    try:
        got = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise Refused('%s: %s' % (what, str(e)[:200]))
    if got.returncode not in ok:
        raise Refused('%s: %s' % (what, (got.stderr or got.stdout).strip()[-300:] or
                                  'ended with %d' % got.returncode))
    return got.stdout


def ntp_read():
    """How the clock is, as timedatectl and chrony say it - nothing changed."""
    out = {'chrony': bool(shutil.which(CHRONYC)), 'tracking': {}, 'sources': []}
    try:
        t = ntp_run([TIMEDATECTL, 'show'], 'timedatectl', ok=(0, 1))
        for line in t.splitlines():
            if '=' in line:
                k, v = line.split('=', 1)
                if k in ('Timezone', 'NTP', 'NTPSynchronized', 'LocalRTC', 'CanNTP'):
                    out[k.lower()] = v[:80]
    except (Refused, OSError):
        pass
    out['time'] = time.time()
    if not out['chrony']:
        return out
    try:
        f = ntp_run([CHRONYC, '-n', '-c', 'tracking'], 'chronyc tracking').strip().split(',')
        if len(f) >= 14:
            out['tracking'] = {'ref_id': f[0][:40], 'ref': f[1][:120], 'stratum': int(f[2] or 0),
                               'ref_time': float(f[3] or 0), 'offset': float(f[4] or 0),
                               'last_offset': float(f[5] or 0), 'rms': float(f[6] or 0),
                               'freq': float(f[7] or 0), 'skew': float(f[9] or 0),
                               'root_delay': float(f[10] or 0), 'root_disp': float(f[11] or 0),
                               'interval': float(f[12] or 0), 'leap': f[13][:40]}
    except (Refused, ValueError, OSError) as e:
        out['said'] = str(e)[:200]
        # chrony there, chronyd not running (1.10.237): said as such, and
        # Step it now starts it.
        if '506' in str(e) or 'Cannot talk to daemon' in str(e):
            out['down'] = True
    try:
        for line in ntp_run([CHRONYC, '-n', '-c', 'sources'], 'chronyc sources').splitlines()[:40]:
            f = line.split(',')
            if len(f) < 10:
                continue
            try:
                out['sources'].append({'mode': f[0][:1], 'state': f[1][:1], 'name': f[2][:120],
                                       'stratum': int(f[3] or 0), 'poll': int(f[4] or 0),
                                       'reach': int(f[5] or 0, 8) if f[5] else 0,
                                       'last_rx': int(f[6]) if f[6].lstrip('-').isdigit() else None,
                                       'offset': float(f[7] or 0), 'measured': float(f[8] or 0),
                                       'error': float(f[9] or 0)})
            except ValueError:
                continue
    except (Refused, OSError):
        pass
    try:
        text = chrony_read()
        out['managed'] = NTP_BEGIN in text
        out['own'] = [l.strip()[:200] for l in text.split('\n')
                      if (l.split() or [''])[0].lower() in ('server', 'pool', 'peer')][:20]
    except OSError:
        out['managed'] = False
    out['conf'] = CHRONY_CONF
    return out


def ntp_checked(r):
    """What the daemon asks for, checked again: every value has one shape."""
    out = {'manage': bool(r.get('manage')), 'servers': [], 'allow': [],
           'makestep': [1.0, 3], 'minsources': 1, 'timezone': ''}
    servers = r.get('servers') or []
    if not isinstance(servers, list):
        raise Refused('the servers are a list')
    for x in servers[:12]:
        if not isinstance(x, dict):
            raise Refused('a server is an object')
        host = str(x.get('host') or '').strip().lower().rstrip('.')
        if re.search(r'[\s\x00-\x1f\x7f]', host):
            raise Refused('%r is not a host name or an address' % host[:80])
        try:
            host = str(plain(host, 'address'))
        except ValueError:
            if not NTP_NAME_RE.match(host):
                raise Refused('%r is not a host name or an address' % host[:80])
        out['servers'].append({'host': host, 'pool': bool(x.get('pool')),
                               'iburst': bool(x.get('iburst', True)),
                               'prefer': bool(x.get('prefer')), 'nts': bool(x.get('nts'))})
    allow = r.get('allow') or []
    if not isinstance(allow, list):
        raise Refused('the networks served are a list')
    for a in allow[:20]:
        try:
            out['allow'].append(str(plain(a, 'network')))
        except ValueError:
            raise Refused('%r is not a network (192.0.2.0/24)' % str(a)[:60])
    try:
        th = float((r.get('makestep') or [1.0, 3])[0])
        lim = int((r.get('makestep') or [1.0, 3])[1])
    except (TypeError, ValueError, IndexError, KeyError, OverflowError):
        raise Refused('makestep is a threshold in seconds and a number of updates')
    if not (0.001 <= th <= 3600) or not (-1 <= lim <= 1000):
        raise Refused('makestep: 0.001 - 3600 s, and -1 (always) to 1000 updates')
    out['makestep'] = [th, lim]
    try:
        out['minsources'] = max(1, min(10, int(r.get('minsources') or 1)))
    except (TypeError, ValueError, OverflowError):
        out['minsources'] = 1
    tz = str(r.get('timezone') or '').strip()
    if tz and not TZ_RE.match(tz):
        raise Refused('%r is not a time zone' % tz[:60])
    out['timezone'] = tz
    if out['manage'] and not out['servers']:
        raise Refused('at least one time server')
    return out


def chrony_read():
    """chrony.conf as it is, whatever its letters (1.10.238): a comment in
    Latin-2 stopped every reading of the clock."""
    with open(CHRONY_CONF, encoding='utf-8', errors='surrogateescape') as f:
        return f.read()


def ntp_conf_text(text, n):
    """chrony.conf with isemon's block (or without it, put back as it was)."""
    # Not set by isemon, and not to be: the file exactly as it is - never
    # rewritten for a final newline (1.10.238).
    if not n['manage'] and NTP_BEGIN not in text and NTP_OFF not in text:
        return text
    lines = text.split('\n')
    if NTP_BEGIN in [l.strip() for l in lines] and NTP_END not in [l.strip() for l in lines]:
        raise Refused('%s has isemon\'s beginning mark and not its end: put it right by hand '
                      '(nothing after the mark is taken away)' % CHRONY_CONF)
    out, inside = [], False
    for l in lines:
        if l.strip() == NTP_BEGIN:
            inside = True
            continue
        if l.strip() == NTP_END:
            inside = False
            continue
        if inside:
            continue
        if l.startswith(NTP_OFF):
            l = l[len(NTP_OFF):]              # the file's own line, put back first
        out.append(l)
    if not n['manage']:
        return '\n'.join(out).rstrip('\n') + '\n'
    kept = [NTP_OFF + l if (l.split() or [''])[0].lower() in NTP_KEYS else l for l in out]
    block = [NTP_BEGIN]
    for x in n['servers']:
        opts = [o for o, on in (('iburst', x['iburst']), ('prefer', x['prefer']),
                                ('nts', x['nts'])) if on]
        block.append(('%s %s %s' % ('pool' if x['pool'] else 'server', x['host'],
                                    ' '.join(opts))).rstrip())
    for a in n['allow']:
        block.append('allow %s' % a)
    block.append('makestep %s %d' % (('%g' % n['makestep'][0]), n['makestep'][1]))
    if n['minsources'] > 1:
        block.append('minsources %d' % n['minsources'])
    block.append(NTP_END)
    if any('\n' in l or '\r' in l for l in block):
        raise Refused('a line of the time servers is not one line')
    return '\n'.join([l.rstrip() for l in kept]).rstrip('\n') + '\n\n' + '\n'.join(block) + '\n'


def ntp_apply(n):
    said = []
    if n['manage'] and not shutil.which(CHRONYC) and not NO_SERVICES:
        if shutil.which('dnf'):
            ntp_run(['dnf', '-y', 'install', 'chrony'], 'dnf install chrony', timeout=240)
            said.append('chrony installed')
        else:
            raise Refused('chrony is not on this machine')
    try:
        had = chrony_read()
    except FileNotFoundError:
        had = 'driftfile /var/lib/chrony/drift\nrtcsync\nlogdir /var/log/chrony\n'
    new = ntp_conf_text(had, n)
    if new != had:
        live = not NO_SERVICES and not NTP_NO_SERVICE
        # chronyd's own word on the file before it is put in (1.10.238): one
        # it refuses stops chronyd, and nothing keeps the clock.
        chronyd = shutil.which('chronyd') if live else None
        if chronyd:
            fd, tmp = tempfile.mkstemp(prefix='.isemon-chrony-', dir=os.path.dirname(CHRONY_CONF))
            try:
                with os.fdopen(fd, 'w', encoding='utf-8', errors='surrogateescape') as f:
                    f.write(new)
                ntp_run([chronyd, '-p', '-f', tmp], 'chronyd -p (the new chrony.conf)')
            finally:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
        if NTP_BEGIN not in had:
            try:
                write_root(CHRONY_CONF + '.isemon-before', had, 0o644)
            except OSError:
                pass
        write_root(CHRONY_CONF, new, 0o644)
        said.append('%s: %s' % (CHRONY_CONF, ', '.join(x['host'] for x in n['servers'])
                                if n['manage'] else 'its own servers again'))
        if live:
            try:
                ntp_run(['systemctl', 'enable', '--now', 'chronyd'], 'systemctl enable chronyd')
                ntp_run(['systemctl', 'restart', 'chronyd'], 'systemctl restart chronyd')
            except Refused as e:
                # Put back as it was, and chronyd started with that.
                write_root(CHRONY_CONF, had, 0o644)
                try:
                    ntp_run(['systemctl', 'restart', 'chronyd'], 'systemctl restart chronyd')
                except Refused:
                    pass
                raise Refused('%s - chrony.conf put back as it was' % e)
            said.append('chronyd restarted')
    if n['timezone']:
        try:
            cur = ntp_run([TIMEDATECTL, 'show', '-p', 'Timezone', '--value'],
                          'timedatectl').strip()
        except Refused:
            cur = ''
        if cur != n['timezone']:
            # Said on its own (1.10.238): the time servers were set all the same.
            try:
                ntp_run([TIMEDATECTL, 'set-timezone', n['timezone']], 'timedatectl set-timezone')
                said.append('time zone: %s' % n['timezone'])
            except Refused as e:
                said.append('the time zone was NOT set: %s' % e)
    if n['manage'] and not NO_SERVICES and not NTP_NO_SERVICE and shutil.which(TIMEDATECTL):
        ntp_run([TIMEDATECTL, 'set-ntp', 'true'], 'timedatectl set-ntp', ok=(0, 1))
    return {'said': said}


def ntp_drop(d):
    """The asking file taken away, whatever the isemon account made of it - a
    folder in its place is removed too, or the path unit would start this
    again and again."""
    try:
        os.unlink(NTP_ASK, dir_fd=d)
    except FileNotFoundError:
        pass
    except OSError:
        try:
            os.rmdir(NTP_ASK, dir_fd=d)
        except OSError:
            # A folder with something in it (1.10.238): moved aside, never
            # read, so the path unit is not started again and again.
            try:
                os.rename(NTP_ASK, '.refused-%s-%d' % (NTP_ASK, int(time.time())),
                          src_dir_fd=d, dst_dir_fd=d)
            except OSError:
                pass


def ntp_part():
    d = web_fd()
    try:
        raw = read_req(NTP_ASK, 65536)
    except FileNotFoundError:
        return
    except (Refused, OSError):
        ntp_drop(d)
        return
    ntp_drop(d)
    out = {'at': time.time(), 'ok': False, 'id': ''}
    try:
        try:
            r = json.loads(raw.decode('utf-8'))
        except ValueError:
            raise Refused('the request does not read')
        if not isinstance(r, dict):
            raise Refused('the request is not an object')
        out['id'] = re.sub(r'[^A-Za-z0-9]', '', str(r.get('id') or ''))[:40]
        what = r.get('do')
        if what == 'read':
            out['data'] = ntp_read()
            if r.get('zones'):
                try:
                    out['data']['zones'] = [z for z in ntp_run(
                        [TIMEDATECTL, 'list-timezones'], 'timedatectl').split()
                        if TZ_RE.match(z)][:700]
                except Refused:
                    pass
        elif what == 'apply':
            out['data'] = ntp_apply(ntp_checked(r))
        elif what == 'sync':
            words = []
            # chronyd not running - installed, never started: started first
            # (1.10.237), or there is nothing to step the clock with.
            if not NO_SERVICES and not NTP_NO_SERVICE and subprocess.run(
                    ['systemctl', 'is-active', '--quiet', 'chronyd'], timeout=30).returncode != 0:
                ntp_run(['systemctl', 'enable', '--now', 'chronyd'], 'systemctl enable chronyd')
                words.append('chronyd started')
                time.sleep(3)
            said = ntp_run([CHRONYC, 'makestep'], 'chronyc makestep').strip()
            ntp_run([CHRONYC, 'burst', '4/4'], 'chronyc burst', ok=(0, 1))
            out['data'] = {'said': words + [said[:200] or 'stepped']}
        else:
            raise Refused('read, apply or sync')
        out['ok'] = True
    except Refused as e:
        out['said'] = str(e)[:400]
    except Exception as e:                              # noqa: BLE001 - said, never lost
        out['said'] = 'it went wrong: %s' % str(e)[:300]
    write_here(NTP_FILE, json.dumps(out))


# ---- the SSH keys root signs in with (1.10.239; after otp's otp_web.py 1.0.158) ----
# Asked in sshkeys.ask: the keys there now (list), one more (add), one taken
# away (drop); answered in sshkeys.json with what is there after it and what
# sshd makes of root. Only /root/.ssh/authorized_keys is ever written, whole:
# a new file of root's, 0600, made beside it and renamed over it, in a folder
# that is not a link (made 0700 when it is not there); the file itself never
# read or written through a link. Every line it does not understand - a
# comment, a key with options before it - is kept as it was. A key is added
# only as one plain public key line (Ed25519, ECDSA, RSA of 3072 bits and
# more), and the last key root signs in with goes only when said again.
SSHKEYS_ASK = 'sshkeys.ask'
SSHKEYS_FILE = 'sshkeys.json'
ROOT_AUTH = os.environ.get('ISEMON_ROOT_AUTHKEYS', '/root/.ssh/authorized_keys')
SSH_KEYGEN = os.environ.get('ISEMON_SSH_KEYGEN', 'ssh-keygen')
SSHD = os.environ.get('ISEMON_SSHD', 'sshd')
SSHKEYS_FRESH_S = 600              # an add or a drop asked longer ago is not done
KEY_TYPES = ('ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521',
             'ssh-rsa', 'sk-ssh-ed25519@openssh.com', 'sk-ecdsa-sha2-nistp256@openssh.com')
KEY_LINE_RE = re.compile(r'^(?P<type>[a-z0-9@.-]+) (?P<blob>[A-Za-z0-9+/]{40,16000}={0,3})'
                         r'(?: (?P<comment>[^\x00-\x1f\x7f]{0,200}))?\Z')


def key_facts(line):
    """(bits, SHA256:..., type) of one public key line, read by ssh-keygen;
    None when it does not read it."""
    if not shutil.which(SSH_KEYGEN):
        return None
    got = subprocess.run([SSH_KEYGEN, '-l', '-E', 'sha256', '-f', '-'], input=line + '\n',
                         capture_output=True, text=True, timeout=20)
    m = re.match(r'^(\d+) (SHA256:[A-Za-z0-9+/=]+) .*\((\w+)\)\s*$', got.stdout.strip())
    if got.returncode != 0 or not m:
        return None
    return int(m.group(1)), m.group(2), m.group(3)


def auth_lines():
    """The lines of root's authorized_keys - none where it is not there.
    Never through a link."""
    try:
        fd = os.open(ROOT_AUTH, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return []
    except OSError as e:
        raise Refused('%s cannot be read: %s' % (ROOT_AUTH, e))
    with os.fdopen(fd, 'r', encoding='utf-8', errors='surrogateescape') as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise Refused('%s is not a plain file' % ROOT_AUTH)
        return f.read(1 << 20).split('\n')


def auth_keys(lines):
    out = []
    for i, ln in enumerate(lines):
        t = ln.strip()
        if not t or t.startswith('#'):
            continue
        facts = key_facts(t)
        m = KEY_LINE_RE.match(t)
        out.append({'line': i, 'fp': facts[1] if facts else '', 'bits': facts[0] if facts else 0,
                    'type': facts[2] if facts else '?',
                    'comment': (m.group('comment') or '') if m else '',
                    'options': not bool(m), 'readable': bool(facts),
                    # The line itself, for the page's export: public halves only.
                    'text': t[:16500].encode('utf-8', 'replace').decode('utf-8', 'replace')})
    return out


def auth_write(lines):
    """root's authorized_keys written whole: its folder made 0700 when it is
    not there, refused when it is a link; a new file of root's, 0600, renamed
    in."""
    folder = os.path.dirname(ROOT_AUTH)
    try:
        st = os.lstat(folder)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise Refused('%s is not a plain folder' % folder)
    except FileNotFoundError:
        os.makedirs(folder, mode=0o700)
        os.chmod(folder, 0o700)
    try:
        if not stat.S_ISREG(os.lstat(ROOT_AUTH).st_mode):
            raise Refused('%s is a link or not a plain file - put the file itself there'
                          % ROOT_AUTH)
    except FileNotFoundError:
        pass
    text = '\n'.join(lines).rstrip('\n') + '\n'
    fd, tmp = tempfile.mkstemp(prefix='.authorized_keys.', dir=folder)
    try:
        os.fchmod(fd, 0o600)
        if os.geteuid() == 0:
            os.fchown(fd, 0, 0)
        with os.fdopen(fd, 'w', encoding='utf-8', errors='surrogateescape') as f:
            fd = None
            f.write(text)
        os.replace(tmp, ROOT_AUTH)
    except BaseException:
        if fd is not None:
            os.close(fd)
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    if shutil.which('restorecon') and not NO_SERVICES:
        subprocess.run(['restorecon', '-R', folder], capture_output=True)


def sshd_says():
    """What sshd makes of root and of keys: a key is no use where it does not
    let root in with one."""
    sshd = shutil.which(SSHD) or ('/usr/sbin/sshd' if os.path.exists('/usr/sbin/sshd') else '')
    if not sshd:
        return {'there': False}
    try:
        got = subprocess.run([sshd, '-T'], capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return {'there': False}
    said = {}
    for ln in got.stdout.splitlines():
        k, _, v = ln.partition(' ')
        if k in ('permitrootlogin', 'pubkeyauthentication', 'passwordauthentication', 'port'):
            said.setdefault(k, re.sub(r'[^A-Za-z0-9-]', '', v.strip())[:40])
    return {'there': True, 'permit_root': said.get('permitrootlogin', ''),
            'pubkey': said.get('pubkeyauthentication', ''),
            'password': said.get('passwordauthentication', ''), 'port': said.get('port', '')}


def sshkeys_do(r):
    do = r.get('do')
    if do in ('add', 'drop'):
        # One left lying from before (an older helper, a run that never
        # came): never done long after it was asked.
        try:
            at = float(r.get('at') or 0)
        except (TypeError, ValueError):
            at = 0.0
        if abs(time.time() - at) > SSHKEYS_FRESH_S:
            raise Refused('that was asked too long ago - ask again on the page if it is still '
                          'wanted')
    lines = auth_lines()
    if do == 'add':
        line = str(r.get('line') or '').strip()
        m = KEY_LINE_RE.match(line)
        if not m or m.group('type') not in KEY_TYPES:
            raise Refused('that is not one public key line (ssh-ed25519 AAAA... comment) - '
                          'options before the key are not taken here')
        facts = key_facts(line)
        if not facts:
            raise Refused('ssh-keygen does not read that key')
        bits, fp, kind = facts
        if kind == 'RSA' and bits < 3072:
            raise Refused('an RSA key of %d bits is too weak: 3072 at least, or ed25519' % bits)
        if kind == 'DSA':
            raise Refused('DSA keys are not taken')
        # There already is no fault: a key of root's handed over again.
        if not any(k['fp'] == fp for k in auth_keys(lines)):
            auth_write([ln for ln in lines if ln.strip()] + [line])
    elif do == 'drop':
        fp = str(r.get('fp') or '')
        keys = auth_keys(lines)
        hit = [k for k in keys if k['fp'] and k['fp'] == fp]
        if not hit:
            raise Refused('no key %s is there' % fp[:80])
        if len(keys) == len(hit) and r.get('last_ok') is not True:
            raise Refused('that is the last key root signs in with here - said again to take it '
                          'away anyway')
        gone = {k['line'] for k in hit}
        auth_write([ln for i, ln in enumerate(lines) if i not in gone])
    elif do != 'list':
        raise Refused('list, add or drop')
    return {'keys': [dict((k, v) for k, v in x.items() if k != 'line')
                     for x in auth_keys(auth_lines())],
            'file': ROOT_AUTH, 'sshd': sshd_says()}


def sshkeys_part():
    try:
        raw = read_req(SSHKEYS_ASK, 65536)
    except FileNotFoundError:
        return
    except (Refused, OSError):
        # A link or a folder in its place: taken away, never followed.
        drop_entry(SSHKEYS_ASK)
        return
    drop_entry(SSHKEYS_ASK)
    out = {'at': time.time(), 'ok': False, 'id': ''}
    try:
        try:
            r = json.loads(raw.decode('utf-8'))
        except ValueError:
            raise Refused('the request does not read')
        if not isinstance(r, dict):
            raise Refused('the request is not an object')
        out['id'] = re.sub(r'[^A-Za-z0-9]', '', str(r.get('id') or ''))[:40]
        out['data'] = sshkeys_do(r)
        out['ok'] = True
    except Refused as e:
        out['said'] = str(e)[:400]
    except Exception as e:                              # noqa: BLE001 - said, never lost
        out['said'] = 'it went wrong: %s' % str(e)[:300]
    write_here(SSHKEYS_FILE, json.dumps(out))


# ---- this machine's network, its name, and switching it off (1.10.228) -----------
# After otp's otp_web.py. Asked in net.ask: what the network is now (read), a
# new one put in NetworkManager with the host name and /etc/hosts (apply), or
# a reboot or a power-off (power). Going back to the old network after a
# change that was not kept is an apply like any other, of the settings the
# daemon kept from before. Every value checked here again: addresses by
# ipaddress, names by NET_NAME_RE, the connection by the list NetworkManager
# gives. Without NetworkManager nothing is changed: the network is set by hand.
NET_ASK = 'net.ask'
NET_FILE = 'net.json'
NMCLI = os.environ.get('ISEMON_NMCLI', 'nmcli')
HOSTNAMECTL = os.environ.get('ISEMON_HOSTNAMECTL', 'hostnamectl')
HOSTS_FILE = os.environ.get('ISEMON_HOSTS_FILE', '/etc/hosts')
POWER_CMD = os.environ.get('ISEMON_POWER_CMD', '')        # tests: a file to write instead
# The console at login (1.10.230): root's choice, switched from Settings -
# About as `isemon --console-at-login on|off` switches it.
CONSOLE_FLAG = os.environ.get('ISEMON_CONSOLE_FLAG', '/etc/isemon-console-login')
CONSOLE_PROFILE = os.environ.get('ISEMON_CONSOLE_PROFILE', '/etc/profile.d/zz-isemon-console.sh')


def console_set(on):
    """/etc/isemon-console-login written beside it and put in its place: a
    link or a pipe found there is replaced, never followed."""
    tmp = '%s.%d.tmp' % (CONSOLE_FLAG, os.getpid())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    try:
        os.write(fd, b'on\n' if on else b'off\n')
        os.fchmod(fd, 0o644)
    finally:
        os.close(fd)
    try:
        os.rename(tmp, CONSOLE_FLAG)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    said = ['the console at login: %s' % ('on' if on else 'off')]
    if not os.path.isfile(CONSOLE_PROFILE):
        said.append('%s is not there - ./install.sh --upgrade puts it in' % CONSOLE_PROFILE)
    return {'said': said, 'on': bool(on)}
IP_CMD = os.environ.get('ISEMON_IP', 'ip')
RESOLV_FILE = os.environ.get('ISEMON_RESOLV', '/etc/resolv.conf')
SYSCTL_IPV6 = os.environ.get('ISEMON_SYSCTL_IPV6', '/etc/sysctl.d/90-isemon-ipv6.conf')
NET_NAME_RE = re.compile(r'^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)'
                         r'(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$')
NM_FIELDS = ['ipv4.method', 'ipv4.addresses', 'ipv4.gateway', 'ipv4.dns', 'ipv4.dns-search',
             'ipv6.method', 'ipv6.addresses', 'ipv6.gateway', 'ipv6.dns']
# All that a change sets, read before it and put back as it was when the
# change is not kept (1.10.234).
NM_BEFORE = NM_FIELDS + ['ipv4.ignore-auto-dns', 'ipv6.dns-search', 'ipv6.ignore-auto-dns']
NM_METHODS = {'ipv4.method': ('auto', 'manual', 'disabled', 'link-local', 'shared'),
              'ipv6.method': ('auto', 'dhcp', 'manual', 'ignore', 'disabled', 'link-local',
                              'shared')}


def net_run(cmd, what, ok=(0,)):
    """A program run with its arguments as a list - never a shell - and its
    own last words when it says no."""
    try:
        got = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except FileNotFoundError:
        raise Refused('%s: %s is not on this machine' % (what, cmd[0]))
    except subprocess.TimeoutExpired:
        raise Refused('%s did not answer in a minute' % what)
    if got.returncode not in ok:
        lines = [x.strip() for x in (got.stderr or got.stdout or '').splitlines() if x.strip()]
        raise Refused('%s: %s' % (what, (lines[-1] if lines else 'it said no')[:240]))
    return got.stdout


def net_iface(text):
    """An address with its prefix (192.0.2.10/24) - and nothing else."""
    text = str(text or '').strip()
    if not ADDR_RE.match(text) or '/' not in text:
        raise ValueError('not an address with its prefix')
    return ipaddress.ip_interface(text)


def nm_fields(con, fields):
    out = net_run([NMCLI, '-t', '-g', ','.join(fields), 'connection', 'show', con],
                  'nmcli connection show')
    vals = out.rstrip('\n').split('\n')
    got = {}
    for k, v in zip(fields, vals + [''] * (len(fields) - len(vals))):
        got[k] = v.replace('\\:', ':').strip()
    return got


def nm_list(text):
    return [x.strip() for x in re.split(r'[,\s]+', text or '') if x.strip() and x.strip() != '--']


def net_read():
    """The network as it is: what the kernel has (ip), what NetworkManager is
    told (nmcli), the host name. Nothing is changed for it."""
    out = {'nm': bool(shutil.which(NMCLI)), 'devices': [], 'con': '', 'dev': '', 'conf': {},
           'live': {'addrs4': [], 'addrs6': [], 'gw4': '', 'gw6': '', 'dns': []}}
    try:
        with open('/proc/sys/net/ipv6/conf/all/disable_ipv6') as f:
            out['ipv6_kernel'] = f.read().strip() == '0'
    except OSError:
        out['ipv6_kernel'] = False
    try:
        for line in net_run([IP_CMD, '-o', 'addr', 'show'], 'ip addr').splitlines():
            f = line.split()
            if len(f) < 4 or f[1] == 'lo':
                continue
            try:
                ifc = ipaddress.ip_interface(f[3])
            except ValueError:
                continue
            if ifc.ip.is_loopback or ifc.ip.is_link_local:
                continue
            (out['live']['addrs4'] if ifc.version == 4 else out['live']['addrs6']).append(
                {'addr': str(ifc), 'dev': f[1].split('@')[0]})
        for fam, key in (('-4', 'gw4'), ('-6', 'gw6')):
            r = net_run([IP_CMD, fam, 'route', 'show', 'default'], 'ip route', ok=(0, 1, 2))
            m = re.search(r'default via (\S+) dev (\S+)', r)
            if m:
                out['live'][key] = m.group(1)
                if key == 'gw4':
                    out['dev'] = m.group(2)
    except Refused:
        pass
    try:
        with open(RESOLV_FILE) as f:
            out['live']['dns'] = [l.split()[1] for l in f if l.startswith('nameserver ')
                                  and len(l.split()) > 1][:6]
    except OSError:
        pass
    try:
        out['hostname'] = net_run([HOSTNAMECTL, '--static'], 'hostnamectl').strip() or \
            os.uname().nodename
    except (Refused, OSError):
        out['hostname'] = os.uname().nodename
    if not out['nm']:
        return out
    try:
        for line in net_run([NMCLI, '-t', '-f', 'DEVICE,TYPE,STATE,CONNECTION', 'device'],
                            'nmcli device').splitlines():
            f = line.replace('\\:', '\x00').split(':')
            f = [x.replace('\x00', ':') for x in f]
            if len(f) >= 4 and f[1] in ('ethernet', 'bond', 'vlan', 'bridge', 'team', 'wifi'):
                out['devices'].append({'dev': f[0], 'type': f[1], 'state': f[2], 'con': f[3]})
    except Refused as e:
        out['nm_said'] = str(e)
    dev = out['dev'] or next((d['dev'] for d in out['devices'] if d['con']), '')
    con = next((d['con'] for d in out['devices'] if d['dev'] == dev and d['con']), '')
    out['dev'], out['con'] = dev, con
    if con:
        try:
            g = nm_fields(con, NM_FIELDS)
            out['conf'] = {'ipv4_method': g['ipv4.method'],
                           'ipv4_addresses': nm_list(g['ipv4.addresses']),
                           'ipv4_gateway': g['ipv4.gateway'] if g['ipv4.gateway'] != '--' else '',
                           'ipv4_dns': nm_list(g['ipv4.dns']),
                           'ipv4_search': nm_list(g['ipv4.dns-search']),
                           'ipv6_method': g['ipv6.method'],
                           'ipv6_addresses': nm_list(g['ipv6.addresses']),
                           'ipv6_gateway': g['ipv6.gateway'] if g['ipv6.gateway'] != '--' else '',
                           'ipv6_dns': nm_list(g['ipv6.dns'])}
        except Refused as e:
            out['nm_said'] = str(e)
    return out


def net_checked(r):
    """An apply request, every value in its one shape."""
    out = {'con': str(r.get('con') or ''), 'reboot_in': 0}
    if not out['con'] or len(out['con']) > 120 or any(c in out['con'] for c in '\n\r\x00'):
        raise Refused('which connection?')
    v4 = r.get('ipv4') if isinstance(r.get('ipv4'), dict) else {}
    try:
        a4 = net_iface(v4.get('addr'))
    except ValueError:
        raise Refused('the IPv4 address is an address with its prefix (192.0.2.10/24)')
    if a4.version != 4:
        raise Refused('the IPv4 address is an address with its prefix (192.0.2.10/24)')
    out['addr4'] = str(a4)
    gw = str(v4.get('gw') or '').strip()
    if gw:
        try:
            g = plain(gw, 'address')
        except ValueError:
            raise Refused('the gateway is one IPv4 address')
        if g.version != 4 or g not in a4.network:
            raise Refused('the gateway %s is not in %s' % (g, a4.network))
        out['gw4'] = str(g)
    else:
        out['gw4'] = ''
    v6 = r.get('ipv6') if isinstance(r.get('ipv6'), dict) else {}
    dns = []
    for d in list(v4.get('dns') or [])[:4] + list(v6.get('dns') or [])[:4]:
        try:
            dns.append(str(plain(d, 'address')))
        except ValueError:
            raise Refused('%r is not the address of a DNS server' % str(d)[:60])
    out['dns4'] = [d for d in dns if ':' not in d]
    out['dns6'] = [d for d in dns if ':' in d]
    search = []
    for s_ in list(v4.get('search') or [])[:6]:
        if not NET_NAME_RE.match(str(s_)):
            raise Refused('%r is not a domain' % str(s_)[:60])
        search.append(str(s_))
    out['search'] = search
    mode = str(v6.get('mode') or 'off')
    if mode not in ('off', 'auto', 'manual', 'keep'):
        raise Refused('IPv6 is off, auto, manual or keep')
    out['mode6'] = mode
    if mode == 'manual':
        try:
            a6 = net_iface(v6.get('addr'))
        except ValueError:
            raise Refused('the IPv6 address is an address with its prefix (2001:db8::10/64)')
        if a6.version != 6 or a6.ip.is_link_local:
            raise Refused('the IPv6 address is a global one with its prefix (2001:db8::10/64)')
        out['addr6'] = str(a6)
        g6 = str(v6.get('gw') or '').strip()
        if g6:
            try:
                gg = plain(g6, 'address')
            except ValueError:
                raise Refused('the IPv6 gateway is one IPv6 address')
            if gg.version != 6:
                raise Refused('the IPv6 gateway is one IPv6 address')
            out['gw6'] = str(gg)
        else:
            out['gw6'] = ''
    host = str(r.get('hostname') or '').strip().rstrip('.').lower()
    # Going back, the old name may be one word, as it may have been.
    if host and (not NET_NAME_RE.match(host) or ('.' not in host and r.get('rollback') is not True)):
        raise Refused('the host name is the whole name: isemon.example.cz')
    out['hostname'] = host
    olds = []
    for o in list(r.get('old') or [])[:8]:
        try:
            olds.append(str(plain(o, 'address')))
        except ValueError:
            pass
    out['old'] = olds
    old_host = str(r.get('old_hostname') or '').strip().lower()
    out['old_hostname'] = old_host if NET_NAME_RE.match(old_host or 'x') else ''
    out['exact'] = nm_exact(r.get('exact')) if r.get('exact') else {}
    try:
        out['reboot_in'] = max(0, min(600, int(r.get('reboot_in') or 0)))
    except (TypeError, ValueError):
        out['reboot_in'] = 0
    return out


def nm_exact(e):
    """What NetworkManager had before a change (NM_BEFORE), to be put back
    as it was: each value checked for what it is."""
    if not isinstance(e, dict):
        raise Refused('what is put back is a list of settings')
    out = {}
    for k in NM_BEFORE:
        if k not in e and k not in NM_METHODS:
            continue                    # not read before the change: left as it is
        v = str(e.get(k) if e.get(k) is not None else '').strip()
        if v == '--':
            v = ''
        if len(v) > 600 or any(c in v for c in '\n\r\x00'):
            raise Refused('%s is not one line' % k)
        if k in NM_METHODS:
            if v not in NM_METHODS[k]:
                raise Refused('%s cannot be %r' % (k, v[:40]))
        elif k.endswith('.addresses'):
            try:
                items = [net_iface(x) for x in nm_list(v)]
            except ValueError:
                raise Refused('%s are addresses with their prefix' % k)
            if any(x.version != (4 if k.startswith('ipv4') else 6) for x in items):
                raise Refused('%s are addresses with their prefix' % k)
            v = ','.join(str(x) for x in items)
        elif k.endswith('.gateway') or k.endswith('.dns'):
            try:
                items = [plain(x, 'address') for x in nm_list(v)]
            except ValueError:
                raise Refused('%s is not addresses' % k)
            if k.endswith('.gateway') and len(items) > 1:
                raise Refused('%s is one address' % k)
            v = ','.join(str(x) for x in items)
        elif k.endswith('.dns-search'):
            items = nm_list(v)
            if any(not NET_NAME_RE.match(x) for x in items):
                raise Refused('%s is not domains' % k)
            v = ','.join(items)
        elif k.endswith('.ignore-auto-dns'):
            if v not in ('', 'yes', 'no'):
                raise Refused('%s is yes or no' % k)
        out[k] = v
    return out


def hosts_lines(text, n):
    """/etc/hosts with this machine's old and new names taken out of the lines
    that are this machine's - those at its old or new addresses, those that
    name it in full, those isemon wrote - and its new ones put in. Other names
    on those lines stay; localhost lines, and other machines' lines, as they are."""
    short = n['hostname'].split('.')[0] if n['hostname'] else ''
    full = set(x for x in (n['hostname'], n['old_hostname']) if x)
    drop_names = set(x for x in (n['hostname'], short, n['old_hostname'],
                                 n['old_hostname'].split('.')[0]) if x)
    mine = set(n['old']) | {n['addr4'].split('/')[0]}
    if n.get('addr6'):
        mine.add(n['addr6'].split('/')[0])
    out = []
    for line in text.splitlines():
        body, hash_, note = line.partition('#')
        f = body.split()
        if f and not f[0].startswith(('127.', '::1')):
            if 'written by isemon' in note:
                continue
            if f[0] in mine or any(x.lower() in full for x in f[1:]):
                names = [x for x in f[1:] if x.lower() not in drop_names]
                if not names:
                    continue
                if len(names) != len(f) - 1:
                    line = ' '.join([f[0]] + names) + ((' ' + hash_ + note) if hash_ else '')
        out.append(line)
    if n['hostname']:
        out.append('%s %s %s    # this machine - written by isemon' % (
            n['addr4'].split('/')[0], n['hostname'], short))
        if n.get('addr6'):
            out.append('%s %s %s    # this machine - written by isemon' % (
                n['addr6'].split('/')[0], n['hostname'], short))
    return '\n'.join(out) + '\n'


def power_after(what, secs):
    """A reboot or a power-off a few seconds from now - after this helper
    has written its answer and the page has had it."""
    if what not in ('reboot', 'poweroff'):
        raise Refused('reboot or poweroff')
    secs = max(3, min(600, int(secs or 5)))
    if POWER_CMD:
        with open(POWER_CMD, 'a') as f:
            f.write('%s %d %s\n' % (what, secs, time.time()))
        return '%s in %d s (written to %s)' % (what, secs, POWER_CMD)
    if NO_SERVICES:
        return '%s in %d s (not here: tests)' % (what, secs)
    net_run(['systemd-run', '--on-active=%ds' % secs, '--unit',
             'isemon-%s-%d' % (what, int(time.time())), '/usr/bin/systemctl', what],
            'systemd-run %s' % what)
    return '%s in %d s' % (what, secs)


def net_apply(n):
    if not shutil.which(NMCLI):
        raise Refused('NetworkManager (nmcli) is not on this machine: set the network by hand')
    cons = [l.replace('\\:', ':') for l in net_run([NMCLI, '-t', '-g', 'NAME', 'connection',
                                                    'show'], 'nmcli connection show').splitlines()]
    if n['con'] not in cons:
        raise Refused('there is no connection %r here' % n['con'])
    said = []
    # What NetworkManager had, handed back: kept by the daemon, so that the
    # old network can be asked for again.
    before = nm_fields(n['con'], NM_BEFORE)
    ex = n.get('exact') or {}
    if ex:
        # Going back: every setting the change set, as it was before it.
        args = [NMCLI, 'connection', 'modify', n['con']]
        for k in NM_BEFORE:
            if k in ex:
                args += [k, ex[k]]
    else:
        args = [NMCLI, 'connection', 'modify', n['con'],
                'ipv4.method', 'manual', 'ipv4.addresses', n['addr4'],
                'ipv4.gateway', n['gw4'], 'ipv4.dns', ','.join(n['dns4']),
                'ipv4.dns-search', ','.join(n['search']), 'ipv4.ignore-auto-dns', 'yes']
        if n['mode6'] == 'off':
            args += ['ipv6.method', 'disabled', 'ipv6.addresses', '', 'ipv6.gateway', '',
                     'ipv6.dns', '']
        elif n['mode6'] == 'auto':
            args += ['ipv6.method', 'auto', 'ipv6.addresses', '', 'ipv6.gateway', '',
                     'ipv6.dns', ','.join(n['dns6'])]
        elif n['mode6'] == 'manual':
            args += ['ipv6.method', 'manual', 'ipv6.addresses', n['addr6'],
                     'ipv6.gateway', n['gw6'], 'ipv6.dns', ','.join(n['dns6'])]
    net_run(args, 'nmcli connection modify')
    said.append('NetworkManager: %s - %s via %s, DNS %s%s' % (
        n['con'], n['addr4'], n['gw4'] or 'no gateway', ', '.join(n['dns4']) or 'none',
        {'off': ', IPv6 off', 'auto': ', IPv6 automatic',
         'manual': ', IPv6 %s' % n.get('addr6'), 'keep': ''}[n['mode6']]))
    if ex:
        on6 = ex['ipv6.method'] not in ('disabled', 'ignore')
    else:
        on6 = {'off': False, 'auto': True, 'manual': True}.get(n['mode6'])
    if on6:
        # IPv6 switched off in the kernel by an earlier hand: on again.
        write_root(SYSCTL_IPV6, '# written by isemon (isemon_web.py) - Settings, Network\n'
                   'net.ipv6.conf.all.disable_ipv6 = 0\nnet.ipv6.conf.default.'
                   'disable_ipv6 = 0\n', 0o644)
    elif on6 is False:
        # Off again: isemon's own file away, so the kernel is as it was
        # before IPv6 was switched on here.
        try:
            with open(SYSCTL_IPV6) as f:
                ours = f.read(200).startswith('# written by isemon')
        except OSError:
            ours = False
        if ours:
            os.unlink(SYSCTL_IPV6)
    if n['hostname']:
        net_run([HOSTNAMECTL, 'set-hostname', n['hostname']], 'hostnamectl set-hostname')
        said.append('host name: %s' % n['hostname'])
    try:
        with open(HOSTS_FILE) as f:
            had = f.read()
    except OSError:
        had = '127.0.0.1 localhost localhost.localdomain\n::1 localhost localhost.localdomain\n'
    new = hosts_lines(had, n)
    if new != had:
        # What it was before isemon's first change, kept: a later change - or
        # going back - never writes over it.
        if not os.path.lexists(HOSTS_FILE + '.isemon-before'):
            try:
                write_root(HOSTS_FILE + '.isemon-before', had, 0o644)
            except OSError:
                pass
        write_root(HOSTS_FILE, new, 0o644)
        said.append('%s: this machine\'s lines' % HOSTS_FILE)
    if n['reboot_in']:
        said.append(power_after('reboot', n['reboot_in']))
    return {'said': said, 'before': before}


def net_part():
    d = web_fd()
    try:
        raw = read_req(NET_ASK, 65536)
    except FileNotFoundError:
        return
    except (Refused, OSError):
        # A link or a folder in its place: taken away, never followed, so
        # the path unit does not start this again and again.
        try:
            os.unlink(NET_ASK, dir_fd=d)
        except OSError:
            try:
                os.rename(NET_ASK, '.refused-%s-%d' % (NET_ASK, int(time.time())),
                          src_dir_fd=d, dst_dir_fd=d)
            except OSError:
                pass
        return
    try:
        os.unlink(NET_ASK, dir_fd=d)
    except OSError:
        pass
    out = {'at': time.time(), 'ok': False, 'id': ''}
    try:
        r = json.loads(raw.decode('utf-8'))
        if not isinstance(r, dict):
            raise Refused('the request is not an object')
        out['id'] = re.sub(r'[^A-Za-z0-9]', '', str(r.get('id') or ''))[:40]
        what = r.get('do')
        if what == 'read':
            out['data'] = net_read()
        elif what == 'apply':
            out['data'] = net_apply(net_checked(r))
        elif what == 'power':
            how = r.get('how')
            if how not in ('reboot', 'poweroff'):
                raise Refused('reboot or poweroff')
            try:
                secs = int(r.get('in') or 5)
            except (TypeError, ValueError):
                secs = 5
            out['data'] = {'said': [power_after(how, secs)]}
        elif what == 'console':
            if not isinstance(r.get('on'), bool):
                raise Refused('the console at login is on or off')
            out['data'] = console_set(r['on'])
        else:
            raise Refused('read, apply, power or console')
        out['ok'] = True
    except Refused as e:
        out['said'] = str(e)[:400]
    except Exception as e:                              # noqa: BLE001
        out['said'] = 'it went wrong: %s' % str(e)[:300]
    write_here(NET_FILE, json.dumps(out))


# ---- updates of the operating system (1.10.239; after otp's otp_web.py 1.0.158) ----
# Asked in osup.ask, answered at once in osup.ans: a look for updates (check)
# or the update of every package (upgrade). The work itself - minutes of dnf
# or apt - runs as a unit of its own (systemd-run), so this oneshot service
# ends and the other asks are served meanwhile, one at a time under a lock of
# its own that is never a link. How far it is and its last lines go into
# osup.json, every second or so: the daemon reads them from there, and keeps
# in the database only how it ended. An ask older than a few minutes is not
# done: one left behind is never started later by surprise.
OSUP_ASK = 'osup.ask'
OSUP_ANS = 'osup.ans'
OSUP_FILE = 'osup.json'
OSUP_LOCK = os.environ.get('ISEMON_OSUP_LOCK', '/run/isemon-osup.lock')
OSUP_PM = os.environ.get('ISEMON_OSUP_PM', '')      # tests: a fake package manager
OSUP_ASK_LIVE_S = 300


def osup_pm():
    if OSUP_PM:
        return 'fake'
    if shutil.which('dnf'):
        return 'dnf'
    if shutil.which('apt-get'):
        return 'apt'
    return ''


def osup_lock_fd():
    """The lock file, opened without following a link - and only a file."""
    fd = os.open(OSUP_LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise Refused('%s is not a file' % OSUP_LOCK)
    return fd


def osup_running():
    import fcntl
    try:
        fd = osup_lock_fd()
    except (OSError, Refused):
        return True                     # a link or a folder there: nothing is started
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    except OSError:
        return True
    finally:
        os.close(fd)


def osup_launch(ident, kind, security=False):
    if not ident:
        raise Refused('the ask has no id')
    if osup_running():
        raise Refused('an update or a look for updates is going on already')
    if not osup_pm():
        raise Refused('neither dnf nor apt-get is on this machine')
    me = os.path.abspath(__file__)
    argv = [sys.executable, '-I', me, '--os-job', ident, kind] + (['security'] if security else [])
    if shutil.which('systemd-run') and not NO_SERVICES and os.path.isdir('/run/systemd/system'):
        got = subprocess.run(['systemd-run', '--unit', 'isemon-os-%s-%s' % (kind, ident[:12]),
                              '--collect', '--quiet', '--property', 'TimeoutStopSec=30min'] + argv,
                             capture_output=True, text=True, timeout=30)
        if got.returncode != 0:
            raise Refused('systemd-run: %s' % (got.stderr or got.stdout).strip()[-200:])
        return
    subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True)


def osup_part():
    try:
        raw = read_req(OSUP_ASK, 4096)
    except FileNotFoundError:
        return
    except (Refused, OSError):
        drop_entry(OSUP_ASK)            # a link or a folder in its place: never followed
        return
    drop_entry(OSUP_ASK)
    out = {'at': time.time(), 'ok': False, 'id': ''}
    try:
        try:
            r = json.loads(raw.decode('utf-8'))
        except ValueError:
            raise Refused('the request does not read')
        if not isinstance(r, dict):
            raise Refused('the request is not an object')
        out['id'] = re.sub(r'[^A-Za-z0-9]', '', str(r.get('id') or ''))[:40]
        kind = r.get('kind')
        if r.get('do') != 'run' or kind not in ('check', 'upgrade'):
            raise Refused('run: check or upgrade')
        try:
            asked = float(r.get('at'))
        except (TypeError, ValueError):
            raise Refused('the ask does not say when it was made')
        if not abs(time.time() - asked) < OSUP_ASK_LIVE_S:
            raise Refused('an old ask, not done: ask again')
        if r.get('security') not in (None, True, False, 0, 1):
            raise Refused('security: true or false')
        # Only the security updates (1.10.257, after otp 1.0.164): an upgrade only.
        security = bool(r.get('security')) and kind == 'upgrade'
        osup_launch(out['id'], kind, security)
        out['ok'] = True
        out['data'] = {'started': kind, 'pm': osup_pm(), 'security': security}
    except Refused as e:
        out['said'] = str(e)[:400]
    except Exception as e:                              # noqa: BLE001
        out['said'] = 'it went wrong: %s' % str(e)[:300]
    write_here(OSUP_ANS, json.dumps(out))


# The packages a restart is needed for once they are updated, as dnf
# needs-restarting -r and Debian's reboot-required name them (otp 1.0.159).
REBOOT_PKGS = {'kernel', 'kernel-core', 'kernel-rt', 'kernel-rt-core', 'kernel-modules',
               'kernel-uek', 'glibc', 'linux-firmware', 'systemd', 'dbus', 'dbus-broker',
               'dbus-daemon', 'microcode_ctl', 'zlib', 'zlib-ng-compat', 'libc6', 'linux-base',
               'intel-microcode', 'amd64-microcode'}


def reboot_for(packages):
    """Which of the packages waiting want a restart once updated."""
    out = []
    for p in packages:
        name = str(p).split()[0] if str(p).split() else ''
        if re.search(r'\.(x86_64|aarch64|noarch|i686|ppc64le|s390x)$', name):
            name = name.rsplit('.', 1)[0]
        if name in REBOOT_PKGS or name.startswith(('linux-image', 'kernel-core-', 'linux-modules')):
            out.append(name)
    return sorted(set(out))


def reboot_now(pm, env, say=None):
    """Whether this machine waits for a restart already."""
    if pm == 'fake':
        return subprocess.run([OSUP_PM, 'needs-restart'], stdout=subprocess.DEVNULL,
                              timeout=300).returncode == 1
    if pm == 'dnf':
        nr = subprocess.run(['dnf', 'needs-restarting', '-r'], capture_output=True,
                            text=True, env=env, timeout=300)
        # 1 is also what dnf says for a command it does not have (no
        # dnf-plugins-core): a restart only when it says so in words.
        need = nr.returncode == 1 and 'reboot' in (nr.stdout or '').lower()
        if need and say:
            say(nr.stdout.strip().splitlines()[0])
        return need
    return os.path.exists('/var/run/reboot-required')


def osup_job(ident, kind, security=False):
    """The work itself, as root, in a process of its own."""
    import fcntl
    try:
        fd = osup_lock_fd()
    except (OSError, Refused):
        return 1
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return 1
    state = {'id': ident, 'kind': kind, 'state': 'running', 'pct': 1, 'lines': [],
             'began': time.time(), 'at': time.time(), 'packages': [], 'reboot': False,
             'pm': osup_pm(), 'phase': 'starting'}
    last = [0.0]

    def put(force=False):
        state['at'] = time.time()
        if force or time.time() - last[0] > 0.8:
            last[0] = time.time()
            state['lines'] = state['lines'][-400:]
            write_here(OSUP_FILE, json.dumps(state))

    def say(line):
        line = line.rstrip()
        if line:
            state['lines'].append(line[:300])
        put()

    env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C',
           'DEBIAN_FRONTEND': 'noninteractive', 'HOME': '/root'}

    def stream(cmd, on_line=None, ok=(0,)):
        say('$ ' + ' '.join(cmd))
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env,
                             stdin=subprocess.DEVNULL, text=True, bufsize=1, errors='replace')
        for ln in p.stdout:
            say(ln)
            if on_line:
                on_line(ln)
        rc = p.wait()
        if rc not in ok:
            raise Refused('%s ended with %d' % (os.path.basename(cmd[0]), rc))
        return rc

    pm = state['pm']
    try:
        put(True)
        if kind == 'check':
            state['phase'] = 'asking for what is new'
            pk = []
            if pm == 'fake':
                stream([OSUP_PM, 'check'], lambda ln: pk.append(ln.strip())
                       if ln.strip() and not ln.startswith('#') else None)
                state['security'] = len([p for p in pk if p.endswith(' security')])
                pk = [p[:-len(' security')] if p.endswith(' security') else p for p in pk]
            elif pm == 'dnf':
                rc_out = []
                stream(['dnf', '-q', '--refresh', 'check-update'], rc_out.append, ok=(0, 100))
                for ln in rc_out:
                    parts = ln.split()
                    if len(parts) >= 3 and '.' in parts[0] and not ln.startswith(' '):
                        pk.append('%s %s' % (parts[0], parts[1]))
                state['security'] = 0
                sec = subprocess.run(['dnf', '-q', 'updateinfo', 'list', '--security'],
                                     capture_output=True, text=True, env=env, timeout=300)
                state['security'] = len([x for x in sec.stdout.splitlines() if x.strip()])
            else:
                stream(['apt-get', 'update'])
                got = subprocess.run(['apt', 'list', '--upgradable'], capture_output=True,
                                     text=True, env=env, timeout=300)
                for ln in got.stdout.splitlines():
                    if '/' in ln and '[upgradable' in ln:
                        name = ln.split('/', 1)[0]
                        ver = ln.split()[1] if len(ln.split()) > 1 else ''
                        pk.append('%s %s' % (name, ver))
            state['packages'] = pk[:1000]
            state['count'] = len(pk)
            # Whether the update will need a restart, told before it is made.
            state['phase'] = 'whether a restart is needed'
            state['reboot_why'] = reboot_for(pk)
            state['reboot_after'] = bool(state['reboot_why'])
            try:
                state['reboot_now'] = reboot_now(pm, env)
            except (OSError, subprocess.SubprocessError):
                state['reboot_now'] = False
            if state['reboot_now']:
                say('a restart is needed already, before any update')
            if state['reboot_why']:
                say('a restart will be needed after the update: %s'
                    % ', '.join(state['reboot_why']))
            state['pct'] = 100
        else:
            seen = {'total': 0, 'done': 0}

            def count(ln):
                m = re.search(r'\b(\d+)/(\d+)\s*$', ln)
                if pm in ('dnf', 'fake') and m and re.search(
                        r'(Upgrading|Installing|Cleanup|Verifying|Running scriptlet|Erasing|'
                        r'Reinstalling|Downgrading|Obsoleting)\s*:', ln):
                    total = int(m.group(2)) * 2          # each one upgraded and then verified
                    seen['total'] = max(seen['total'], total)
                    seen['done'] = min(seen['total'], seen['done'] + 1)
                    state['phase'] = 'putting the packages in'
                if pm in ('dnf', 'fake') and ln.startswith('Downloading Packages'):
                    state['phase'] = 'downloading'
                    state['pct'] = max(state['pct'], 8)
                if pm == 'apt':
                    m2 = re.match(r'^(\d+) upgraded, (\d+) newly installed', ln)
                    if m2:
                        seen['total'] = (int(m2.group(1)) + int(m2.group(2))) * 2
                    if ln.startswith(('Unpacking ', 'Setting up ')):
                        seen['done'] += 1
                        state['phase'] = 'putting the packages in'
                    if ln.startswith('Get:'):
                        state['phase'] = 'downloading'
                        state['pct'] = max(state['pct'], 8)
                if seen['total']:
                    state['pct'] = max(state['pct'], min(97, 10 + int(87 * seen['done'] /
                                                                      seen['total'])))
            state['phase'] = 'asking for what is new'
            # Only the security updates where asked (1.10.257, after otp
            # 1.0.164): dnf's own --security, unattended-upgrade on apt (it
            # takes the security sources only, as Debian and Ubuntu set it up).
            state['security_only'] = bool(security)
            if pm == 'fake':
                stream([OSUP_PM, 'upgrade'] + (['security'] if security else []), count)
            elif pm == 'dnf':
                stream(['dnf', '-y', '--refresh', 'upgrade'] + (['--security'] if security else []),
                       count)
            elif security:
                if not shutil.which('unattended-upgrade'):
                    raise Refused('only the security updates: unattended-upgrade is not on this '
                                  'machine (apt install unattended-upgrades)')
                stream(['apt-get', 'update'])
                state['pct'] = max(state['pct'], 5)
                stream(['unattended-upgrade', '-v'], count)
            else:
                stream(['apt-get', 'update'])
                state['pct'] = max(state['pct'], 5)
                stream(['apt-get', '-y', '-o', 'Dpkg::Options::=--force-confdef', '-o',
                        'Dpkg::Options::=--force-confold', 'upgrade'], count)
            state['phase'] = 'whether a restart is needed'
            state['reboot'] = reboot_now(pm, env, say)
            state['pct'] = 100
        state['state'] = 'done'
        state['phase'] = 'done'
    except Refused as e:
        state.update(state='failed', said=str(e)[:300])
    except Exception as e:                              # noqa: BLE001
        state.update(state='failed', said='it broke: %s' % str(e)[:300])
    finally:
        try:
            put(True)
        finally:
            os.close(fd)
    return 0


# ---- the otp logs over TLS (1.10.245; for otp's Settings → isemon → Encrypted sending) ----
# Asked in otptls.ask: how it is (read), the receiver put in with a
# certificate given (apply: ca, cert, key - from the file otp made, or
# pasted), one made here by an authority of this machine's own (make), the
# nodes or the port changed with the certificate as it is (set), or taken
# away (off); answered in otptls.json. What is written is root's alone:
# /etc/pki/rsyslog/otp/ (0750; the keys 0600) and one rsyslog file,
# /etc/rsyslog.d/10-otp-tls.conf, written here whole - never a file taken
# from otp's zip as it is: the nodes' names and the mode are read from it on
# the daemon's side and checked again here. rsyslog is asked (rsyslogd -N1)
# before it is restarted, and every file is put back as it was when it says
# no or does not listen after. The plain input on 514 is never touched: a
# node not switched over yet goes on sending there.
OTPTLS_ASK = 'otptls.ask'
OTPTLS_FILE = 'otptls.json'
# 99-: read after every file that loads imtcp (1.10.246). rsyslog reads
# rsyslog.d in order, and an input of a module not loaded yet is refused
# ("input module name 'imtcp' is unknown", and every TLS parameter "not
# known") - 10-otp-tls.conf, the name otp's README gives it, came before the
# 10-remote-logs.conf of a site that loads imtcp there. One by that name -
# isemon 1.10.245's, or one put in by hand - is taken away when this one is
# written: two inputs on one port and rsyslog refuses both.
OTPTLS_CONF = os.environ.get('ISEMON_OTPTLS_CONF', '/etc/rsyslog.d/99-otp-tls.conf')
OTPTLS_OLD = os.environ.get('ISEMON_OTPTLS_OLD', '/etc/rsyslog.d/10-otp-tls.conf')
OTPTLS_DIR = os.environ.get('ISEMON_OTPTLS_DIR', '/etc/pki/rsyslog/otp')
RSYSLOGD = os.environ.get('ISEMON_RSYSLOGD', 'rsyslogd')
RSYSLOG_MODDIRS = os.environ.get('ISEMON_RSYSLOG_MODDIR', '/usr/lib64/rsyslog:/usr/lib/rsyslog:'
                                 '/usr/lib/x86_64-linux-gnu/rsyslog:/usr/lib/aarch64-linux-gnu/rsyslog')
OTPTLS_MARK = '# isemon: the otp logs over TLS'
OTPTLS_FRESH_S = 600
OTPTLS_NAME_RE = re.compile(r'^(?=.{1,253}\Z)(\*\.)?[A-Za-z0-9]([A-Za-z0-9_-]{0,62})'
                            r'(\.[A-Za-z0-9]([A-Za-z0-9_-]{0,62}))*\.?\Z')
OTPTLS_DRIVERS = {'gtls': ('lmnsd_gtls.so', 'rsyslog-gnutls'),
                  'ossl': ('lmnsd_ossl.so', 'rsyslog-openssl')}


def otptls_path(name):
    return os.path.join(OTPTLS_DIR, name)


def rsyslog_conf_files():
    files = []
    for one in RSYSLOG_FILES.split(':'):
        if os.path.isdir(one):
            files += sorted(os.path.join(one, n) for n in os.listdir(one) if n.endswith('.conf'))
        elif os.path.isfile(one):
            files.append(one)
    return files


def rsyslog_text(path):
    try:
        with open(path, encoding='utf-8', errors='replace') as f:
            text = f.read(1 << 20)
    except OSError:
        return ''
    return '\n'.join(l for l in text.split('\n') if not l.strip().startswith('#'))


def otptls_others():
    """What the rest of rsyslog's files already say: whether imtcp is loaded,
    whether the default TLS files are set, and the ports listened on."""
    mine = (os.path.realpath(OTPTLS_CONF), os.path.realpath(OTPTLS_OLD))
    out = {'imtcp': [], 'global': [], 'ports': []}
    for path in rsyslog_conf_files():
        if os.path.realpath(path) in mine:
            continue
        text = rsyslog_text(path)
        if re.search(r'module\s*\(\s*load\s*=\s*"imtcp"', text) or \
                re.search(r'(?m)^\s*\$ModLoad\s+imtcp\b', text):
            out['imtcp'].append(path)
        if re.search(r'DefaultNetstreamDriver(CAFile|CertFile|KeyFile)', text):
            out['global'].append(path)
    for p in rsyslog_ports():
        if os.path.realpath(os.path.join(os.path.dirname(OTPTLS_CONF), p['file'])) not in mine:
            out['ports'].append(p)
    return out


def rsyslog_version():
    """(8, 2310) of `rsyslogd -v`, or None."""
    try:
        got = subprocess.run([RSYSLOGD, '-v'], capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return None
    m = re.search(r'rsyslogd\s+(\d+)\.(\d+)', got.stdout or '')
    return (int(m.group(1)), int(m.group(2))) if m else None


def otptls_driver():
    """The stream driver there is here: gtls (rsyslog-gnutls, what otp's
    README names) or ossl (rsyslog-openssl, which install.sh puts in)."""
    dirs = [d for d in RSYSLOG_MODDIRS.split(':') if d]
    for name, (lib, _) in OTPTLS_DRIVERS.items():
        if any(os.path.exists(os.path.join(d, lib)) for d in dirs):
            return name
    return ''


def otptls_driver_get(said):
    got = otptls_driver()
    if got or NO_SERVICES:
        return got or 'gtls'
    for pm, args in (('dnf', ['install', '-y']), ('apt-get', ['install', '-y'])):
        if shutil.which(pm):
            try:
                r = subprocess.run([pm] + args + ['rsyslog-gnutls'],
                                   capture_output=True, text=True, timeout=600)
            except (OSError, subprocess.TimeoutExpired):
                break
            if r.returncode == 0:
                said.append('rsyslog-gnutls installed')
            break
    got = otptls_driver()
    if not got:
        raise Refused('rsyslog has no TLS driver here: install rsyslog-gnutls (or '
                      'rsyslog-openssl) and try again')
    return got


def otptls_names(text, what, most=64):
    names = [n.strip().rstrip('.') for n in re.split(r'[\s,;]+', str(text or '')) if n.strip()]
    if len(names) > most:
        raise Refused('%s: %d at most' % (what, most))
    for n in names:
        try:
            plain(n, 'address')
            continue
        except ValueError:
            pass
        if not OTPTLS_NAME_RE.match(n):
            raise Refused('%s: %r is not a name' % (what, n[:80]))
    return list(dict.fromkeys(names))


def otptls_port(v):
    try:
        port = int(v or 6514)
    except (TypeError, ValueError):
        raise Refused('the port is a number')
    if not 1 <= port <= 65535 or port == 514:
        raise Refused('the port is 1 to 65535, and not 514 - that one is the plain logs\'')
    return port


def cert_facts(pem):
    """What a certificate says of itself."""
    out = openssl(['x509', '-noout', '-nameopt', 'RFC2253', '-subject', '-issuer', '-enddate',
                   '-startdate', '-fingerprint', '-sha256', '-ext', 'subjectAltName'],
                  'the certificate', pem)
    f = {'subject': '', 'issuer': '', 'until': '', 'from': '', 'fp': '', 'names': []}
    for line in out.splitlines():
        line = line.strip()
        for key, word in (('subject', 'subject='), ('issuer', 'issuer='), ('until', 'notAfter='),
                          ('from', 'notBefore='), ('fp', 'sha256 Fingerprint=')):
            if line.startswith(word):
                f[key] = line[len(word):].strip()
        if line.startswith(('DNS:', 'IP Address:', 'IP:')):
            f['names'] += [x.strip().split(':', 1)[1] for x in line.split(',') if ':' in x]
    try:
        import calendar
        f['until_t'] = calendar.timegm(time.strptime(f['until'].replace(' GMT', ''),
                                                     '%b %d %H:%M:%S %Y'))
    except ValueError:
        f['until_t'] = 0
    cn = re.search(r'(?:^|,)CN=([^,]+)', f['subject'])
    if cn and cn.group(1) not in f['names']:
        f['cn'] = cn.group(1)
    return f


def pem_certs(text):
    return [m.group(0) + '\n' for m in re.finditer(
        r'-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----', text or '')]


def otptls_state():
    try:
        with open(otptls_path('.isemon.json')) as f:
            got = json.load(f)
        return got if isinstance(got, dict) else {}
    except (OSError, ValueError):
        return {}


def otptls_conf_now(path=None):
    """The file there now: whether it is isemon's, and what it says - the
    one by the old name when the new one is not there."""
    if path is None:
        got = otptls_conf_now(OTPTLS_CONF)
        if not got.get('there') and os.path.lexists(OTPTLS_OLD):
            got = dict(otptls_conf_now(OTPTLS_OLD), old=OTPTLS_OLD)
        return got
    try:
        with open(path, encoding='utf-8', errors='replace') as f:
            text = f.read(65536)
    except FileNotFoundError:
        return {'there': False}
    except OSError as e:
        return {'there': True, 'said': str(e)[:200]}
    body = '\n'.join(l for l in text.split('\n') if not l.strip().startswith('#'))
    port = re.search(r'port\s*=\s*"([0-9]{1,5})"', body)
    auth = re.search(r'AuthMode\s*=\s*"([a-z0-9/]+)"', body, re.I)
    drv = re.search(r'StreamDriver\.Name\s*=\s*"([a-z]+)"', body, re.I)
    peers = re.search(r'PermittedPeer\s*=\s*\[([^\]]*)\]', body, re.I) or \
        re.search(r'PermittedPeer\s*=\s*"([^"]*)"', body, re.I)
    return {'there': True, 'mine': OTPTLS_MARK in text,
            'port': int(port.group(1)) if port else 0,
            'auth': auth.group(1) if auth else '', 'driver': drv.group(1) if drv else '',
            'peers': re.findall(r'"([^"]+)"', peers.group(0)) if peers else []}


def listening(port):
    if NO_SERVICES or not shutil.which('ss'):
        return None
    got = subprocess.run(['ss', '-Hltnp', 'sport = :%d' % port], capture_output=True, text=True)
    return bool(got.stdout.strip()) if got.returncode == 0 else None


TLS_WORDS = r'gtls|gnutls|ossl|openssl|tls|certificate|permitted|peer|netstream|imtcp|6514'
TLS_BAD = (r'error|fail|not permitted|unknown ca|untrusted|expired|not yet valid|denied|refus|'
           r'could not|cannot|invalid|unable|abort|alert|bad |mismatch')
# A node that hangs up without a goodbye - otp's "Try it", a node restarted -
# is said by GnuTLS as an error -110 and the session closed: no trouble.
TLS_BENIGN = (r'error -110|broken connection|premature termination|non-properly terminated|'
              r'will be closed due to error')


def rsyslog_since():
    """When rsyslog was started last, as seconds since 1970 - or None."""
    try:
        got = subprocess.run(['systemctl', 'show', 'rsyslog', '-p', 'ActiveEnterTimestamp',
                              '--timestamp=unix', '--value'], capture_output=True, text=True,
                             timeout=20)
        m = re.match(r'^@(\d+)', got.stdout.strip())
        return int(m.group(1)) if m else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def rsyslog_trouble(minutes=30, problems=True):
    """What rsyslog said about TLS that went wrong - since it was started
    last, so that a set-up refused before it, or rsyslog's own words when it
    starts, are not taken for trouble now (1.10.248). problems=False: every
    line about TLS (why a restart did not listen)."""
    if NO_SERVICES or not shutil.which('journalctl'):
        return []
    since = '-%dmin' % minutes
    began = rsyslog_since() if problems else None
    if began and began > time.time() - minutes * 60:
        since = '@%d' % began
    got = subprocess.run(['journalctl', '-u', 'rsyslog', '--since', since,
                          '--no-pager', '-o', 'short-iso', '-n', '400'],
                         capture_output=True, text=True, timeout=30)
    hit = [l for l in got.stdout.splitlines() if re.search(TLS_WORDS, l, re.I)
           and not l.startswith('-- ') and (not problems or (re.search(TLS_BAD, l, re.I) and not re.search(TLS_BENIGN, l, re.I)))]
    return [l[:300] for l in hit[-8:]]


def fw_port_open(port):
    """Whether firewalld lets the port in (None: not firewalld)."""
    if fw_backend() != 'firewalld':
        return None
    got = subprocess.run(['firewall-cmd', '--query-port=%d/tcp' % port], capture_output=True)
    return got.returncode == 0


def otptls_read():
    conf = otptls_conf_now()
    st = otptls_state()
    out = {'conf': conf, 'file': conf.get('old') or OTPTLS_CONF, 'dir': OTPTLS_DIR, 'version': '',
           'driver_there': otptls_driver(), 'how': st.get('how') or '',
           'fw': fw_backend(), 'others': []}
    v = rsyslog_version()
    out['version'] = '%d.%d' % v if v else ''
    try:
        out['others'] = [p for p in otptls_others()['ports']]
    except Exception:                                   # noqa: BLE001
        pass
    for key, name in (('cert', 'isemon.crt'), ('ca', 'ca.pem'), ('own_ca', 'isemon-ca.crt')):
        try:
            with open(otptls_path(name)) as f:
                pem = f.read(400000)
            certs = pem_certs(pem)
            if key == 'ca':
                out['ca'] = [cert_facts(c) for c in certs[:6]]
            else:
                out[key] = cert_facts(certs[0]) if certs else {}
                if key == 'own_ca':
                    out['own_ca']['pem'] = certs[0] if certs else ''
        except (OSError, Refused):
            pass
    if conf.get('there') and conf.get('port'):
        out['listening'] = listening(conf['port'])
        out['fw_open'] = fw_port_open(conf['port'])
    out['trouble'] = rsyslog_trouble()
    # Whatever is left in the folder - from a set-up refused half way, say -
    # so that Remove… has something to take away (1.10.247).
    try:
        out['left'] = sorted(n for n in os.listdir(OTPTLS_DIR) if n != '.isemon.json')[:20] \
            if os.path.isdir(OTPTLS_DIR) and not os.path.islink(OTPTLS_DIR) else []
    except OSError:
        out['left'] = []
    return out


def otptls_text(port, auth, peers, driver, per_input, load):
    lines = [
        '# %s' % OTPTLS_CONF,
        OTPTLS_MARK + ' - written by isemon (Settings → The OTP logs →',
        '# Encrypted receiving). Changed there, not here: a hand edit is written over',
        '# the next time it is set there. The plain input on 514 is not this file\'s:',
        '# a node that still sends plain goes on arriving there.',
        '#',
        '# What arrives here is filed by the same rule as what arrives plain',
        '# (11-otp.conf): /var/log/remote/<host>/totp.cgi.log and radius-detail.log.',
        '']
    files = ('CAFile', otptls_path('ca.pem')), ('CertFile', otptls_path('isemon.crt')), \
        ('KeyFile', otptls_path('isemon.key'))
    if not per_input:
        lines += ['global('] + ['  DefaultNetstreamDriver%s="%s"' % f for f in files] + [')']
    if load:
        lines.append('module(load="imtcp")')
    inp = ['input(type="imtcp" port="%d" name="otp-tls"' % port,
           '      StreamDriver.Name="%s"' % driver,
           '      StreamDriver.Mode="1"',
           '      StreamDriver.AuthMode="%s"' % auth]
    if per_input:
        inp += ['      StreamDriver.%s="%s"' % f for f in files]
    if auth == 'x509/name':
        inp.append('      PermittedPeer=[%s]' % ', '.join('"%s"' % p for p in peers))
    inp[-1] += ')'
    return '\n'.join(lines + inp) + '\n'


def otptls_ext(names):
    alt = []
    for n in names:
        try:
            plain(n, 'address')
            alt.append('IP:' + n)
        except ValueError:
            alt.append('DNS:' + n)
    return ('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,'
            'keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=%s\n'
            % ','.join(alt))


def otptls_make(names, work):
    """A certificate for these names from this machine's own authority - made
    once, in OTPTLS_DIR, and kept: one made again is trusted by otp as it is.
    Returns (cert, key, the authority's certificate)."""
    ca_key, ca_crt = otptls_path('isemon-ca.key'), otptls_path('isemon-ca.crt')
    os.makedirs(OTPTLS_DIR, mode=0o750, exist_ok=True)
    if not (os.path.exists(ca_key) and os.path.exists(ca_crt)):
        host = re.sub(r'[^A-Za-z0-9.-]', '', os.uname()[1])[:60] or 'isemon'
        tk, tc = os.path.join(work, 'ca.key'), os.path.join(work, 'ca.crt')
        openssl(['req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-sha256', '-days', '3650',
                 '-subj', '/CN=isemon %s - the otp logs' % host, '-keyout', tk, '-out', tc,
                 '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:0',
                 '-addext', 'keyUsage=critical,keyCertSign,cRLSign'], 'the authority')
        with open(tk) as f:
            write_root(ca_key, f.read(), 0o600)
        with open(tc) as f:
            write_root(ca_crt, f.read(), 0o644)
    k, csr, crt, ext = (os.path.join(work, n) for n in ('s.key', 's.csr', 's.crt', 's.ext'))
    with open(ext, 'w') as f:
        f.write(otptls_ext(names))
    openssl(['req', '-new', '-newkey', 'rsa:3072', '-nodes', '-sha256', '-subj',
             '/CN=%s' % names[0], '-keyout', k, '-out', csr], 'the key')
    openssl(['x509', '-req', '-in', csr, '-CA', ca_crt, '-CAkey', ca_key, '-CAcreateserial',
             '-CAserial', os.path.join(work, 'serial'), '-days', '825', '-sha256',
             '-extfile', ext, '-out', crt], 'the certificate')
    with open(crt) as f:
        cert = f.read()
    with open(k) as f:
        key = f.read()
    with open(ca_crt) as f:
        own = f.read()
    return cert, key, own


def otptls_restart(port, said):
    if NO_SERVICES:
        return
    got = subprocess.run(['systemctl', 'restart', 'rsyslog'], capture_output=True, text=True,
                         timeout=120)
    if got.returncode != 0:
        raise Refused('rsyslog would not restart: %s' % (got.stderr or got.stdout).strip()[-300:])
    if port:
        end = time.time() + 12
        while time.time() < end:
            if listening(port) is not False:
                said.append('rsyslog listens on %d/tcp' % port)
                return
            time.sleep(0.5)
        raise Refused('rsyslog restarted but does not listen on %d/tcp: %s' % (
            port, ' | '.join(rsyslog_trouble(2, problems=False)[-3:]) or
            'journalctl -u rsyslog says why'))


def otptls_firewalld(port, add, st, said):
    if fw_backend() != 'firewalld':
        return
    if add:
        if fw_port_open(port):
            return
        for extra in ([], ['--permanent']):
            subprocess.run(['firewall-cmd'] + extra + ['--add-port=%d/tcp' % port],
                           capture_output=True)
        st['fw_added'] = port
        said.append('firewalld lets %d/tcp in' % port)
    elif st.get('fw_added'):
        for extra in ([], ['--permanent']):
            subprocess.run(['firewall-cmd'] + extra + ['--remove-port=%d/tcp' % int(
                st['fw_added'])], capture_output=True)
        said.append('firewalld no longer lets %d/tcp in' % int(st['fw_added']))
        st.pop('fw_added', None)


def otptls_selinux(port, said):
    if port == 6514 or NO_SERVICES or not shutil.which('semanage'):
        return
    got = subprocess.run(['getenforce'], capture_output=True, text=True) \
        if shutil.which('getenforce') else None
    if got is None or got.stdout.strip() == 'Disabled':
        return
    for how in ('-a', '-m'):
        r = subprocess.run(['semanage', 'port', how, '-t', 'syslog_tls_port_t', '-p', 'tcp',
                            str(port)], capture_output=True, text=True, timeout=120)
        if r.returncode == 0:
            said.append('SELinux lets rsyslog listen on %d/tcp' % port)
            return


def otptls_apply(r):
    """The receiver put in - or changed (set), or taken away (off)."""
    do = r.get('do')
    said = []
    v = rsyslog_version()
    if do not in ('off', 'remove') and not NO_SERVICES and v is None:
        raise Refused('rsyslog is not installed here (dnf install rsyslog)')
    if do not in ('off', 'remove') and v is not None and v < (8, 2106):
        raise Refused('rsyslog %d.%d cannot have an encrypted input beside the plain one: '
                      '8.2106 or later is needed (AlmaLinux / RHEL 9)' % v)
    per_input = v is None or v >= (8, 2108)
    st = otptls_state()
    now = otptls_conf_now()
    paths = [OTPTLS_CONF, OTPTLS_OLD, otptls_path('ca.pem'), otptls_path('isemon.crt'),
             otptls_path('isemon.key'), otptls_path('.isemon.json')]
    snap = snapshot(paths)
    old_port = now.get('port') if now.get('there') else 0
    # One set up by hand before: kept beside, once, never loaded again.
    for path in (OTPTLS_CONF, OTPTLS_OLD):
        had = otptls_conf_now(path)
        if had.get('there') and not had.get('mine') and \
                not os.path.exists(path + '.isemon-before'):
            shutil.copy2(path, path + '.isemon-before')
            said.append('the file there before is kept as %s.isemon-before' % path)
    restarted = False
    try:
        # The one by the old name goes, whatever is asked (put back when
        # rsyslog says no).
        try:
            os.unlink(OTPTLS_OLD)
            said.append('%s taken away - %s takes its place' % (OTPTLS_OLD, OTPTLS_CONF))
        except FileNotFoundError:
            pass
        if do in ('off', 'remove'):
            # Off: the certificate and its key stay, to be switched on again.
            # Removed (1.10.246): they go too, and the authority made here.
            try:
                os.unlink(OTPTLS_CONF)
            except FileNotFoundError:
                pass
            otptls_restart(0, said)
            restarted = True
            otptls_firewalld(old_port, False, st, said)
            said.append('the encrypted input is taken away; the plain one is as it was')
            if do == 'off':
                st.update(on=False, at=time.time())
                if os.path.isdir(OTPTLS_DIR):
                    write_root(otptls_path('.isemon.json'), json.dumps(st), 0o600)
                return said
            gone = []
            if os.path.isdir(OTPTLS_DIR) and not os.path.islink(OTPTLS_DIR):
                for name in sorted(os.listdir(OTPTLS_DIR)):
                    if name in ('isemon.key', 'isemon.crt', 'ca.pem', 'isemon-ca.key',
                                'isemon-ca.crt', 'isemon-ca.srl', '.isemon.json'):
                        try:
                            os.unlink(otptls_path(name))
                            gone.append(name)
                        except OSError:
                            pass
                try:
                    os.rmdir(OTPTLS_DIR)
                except OSError:
                    pass
            if gone:
                said.append('the certificate, its key and the authorities taken away (%s)'
                            % OTPTLS_DIR)
            return said
        port = otptls_port(r.get('port'))
        mutual = bool(r.get('mutual'))
        peers = otptls_names(r.get('peers'), 'the nodes') if mutual else []
        auth = 'x509/name' if peers else ('x509/certvalid' if mutual else 'anon')
        others = otptls_others()
        if any(int(p['port']) == port and p['proto'] == 'tcp' for p in others['ports']):
            raise Refused('rsyslog listens on %d/tcp already (%s): choose another port' % (
                port, ', '.join(sorted({p['file'] for p in others['ports']
                                        if int(p['port']) == port}))))
        if not per_input and others['global']:
            raise Refused('rsyslog %d.%d takes the TLS files once for all of it, and %s sets '
                          'them already: rsyslog 8.2108 or later takes them per input' % (
                              v + (', '.join(others['global']),)))
        os.makedirs(OTPTLS_DIR, mode=0o750, exist_ok=True)
        os.chmod(OTPTLS_DIR, 0o750)
        with tempfile.TemporaryDirectory(prefix='isemon-otptls-') as work:
            if do == 'make':
                names = otptls_names(r.get('names'), 'the names of this machine', 20)
                if not names:
                    raise Refused('the names the nodes reach this machine by: one at least')
                cert, key, own = otptls_make(names, work)
                trust = pem_certs(str(r.get('otp_ca') or ''))
                if mutual and not trust:
                    raise Refused('mutual TLS: otp\'s authority (its ca.pem) is needed, to '
                                  'know the nodes by')
                ca = ''.join(trust) + own
                st.update(how='made', names=names, otp_ca=bool(trust))
                said.append('a certificate made for %s, by this machine\'s own authority'
                            % ', '.join(names))
            elif do == 'apply':
                got = pem_set(r.get('cert'), r.get('key'), r.get('chain'))
                if not got:
                    raise Refused('the certificate and its key')
                cert, key = got['cert'] + got['chain'], got['key']
                ca_text = str(r.get('ca') or '')
                if ca_text.strip() and not CERT_RE.match(ca_text.strip()):
                    raise Refused('the authority is not PEM (-----BEGIN CERTIFICATE-----)')
                ca = ''.join(pem_certs(ca_text)) or ''.join(pem_certs(got['chain'])) or \
                    pem_certs(cert)[0]
                if mutual and not pem_certs(ca_text):
                    raise Refused('mutual TLS: otp\'s authority (its ca.pem) is needed, to '
                                  'know the nodes by')
                st.update(how=str(r.get('how') or 'given')[:20], names=[],
                          otp_ca=bool(pem_certs(ca_text)))
            elif do == 'set':
                if not (os.path.exists(otptls_path('isemon.crt')) and
                        os.path.exists(otptls_path('isemon.key'))):
                    raise Refused('there is no certificate here yet: set it up first')
                cert = key = ca = None
                extra = pem_certs(str(r.get('otp_ca') or ''))
                if extra:
                    with open(otptls_path('ca.pem')) as f:
                        have = pem_certs(f.read())
                    ca = ''.join(have + [c for c in extra if c not in have])
                    st['otp_ca'] = True
                if mutual and not st.get('otp_ca', True):
                    raise Refused('mutual TLS: otp\'s authority (its ca.pem) is needed, to '
                                  'know the nodes by - the certificate here was set up without '
                                  'it')
            else:
                raise Refused('read, apply, make, set, off or remove')
            if cert is not None:
                cert_facts(pem_certs(cert)[0])
                write_root(otptls_path('isemon.key'), key, 0o600)
                write_root(otptls_path('isemon.crt'), cert, 0o644)
            if ca is not None:
                write_root(otptls_path('ca.pem'), ca, 0o644)
        driver = otptls_driver_get(said)
        text = otptls_text(port, auth, peers, driver, per_input, not others['imtcp'])
        write_root(OTPTLS_CONF, text, 0o644)
        if shutil.which('restorecon') and not NO_SERVICES:
            subprocess.run(['restorecon', '-R', os.path.dirname(OTPTLS_DIR)], capture_output=True)
        if not NO_SERVICES or os.environ.get('ISEMON_RSYSLOGD'):
            chk = subprocess.run([RSYSLOGD, '-N1'], capture_output=True, text=True, timeout=120)
            if chk.returncode != 0:
                bad = [l for l in (chk.stderr + chk.stdout).splitlines()
                       if re.search(r'error|warn', l, re.I)][:3]
                raise Refused('rsyslog does not take it, so nothing was changed: %s' % (
                    ' | '.join(bad) or 'rsyslogd -N1 says why'))
        otptls_selinux(port, said)
        restarted = True
        otptls_restart(port, said)
        if old_port and old_port != port:
            otptls_firewalld(old_port, False, st, said)
        otptls_firewalld(port, True, st, said)
        st.update(on=True, port=port, auth=auth, peers=peers, at=time.time())
        write_root(otptls_path('.isemon.json'), json.dumps(st), 0o600)
        said.append('rsyslog takes the otp logs over TLS on %d/tcp (%s)' % (port, {
            'anon': 'it checks no node', 'x509/certvalid': 'from any node with a certificate '
            'of otp\'s authority', 'x509/name': 'from %s' % ', '.join(peers)}[auth]))
        return said
    except BaseException:
        put_back(snap)
        if restarted:
            try:
                otptls_restart(0, [])
            except Exception:                           # noqa: BLE001
                pass
        raise


def otptls_part():
    try:
        raw = read_req(OTPTLS_ASK, 262144)
    except FileNotFoundError:
        return
    except (Refused, OSError):
        drop_entry(OTPTLS_ASK)            # a link or a folder in its place: never followed
        return
    drop_entry(OTPTLS_ASK)
    out = {'at': time.time(), 'ok': False, 'id': ''}
    try:
        try:
            r = json.loads(raw.decode('utf-8'))
        except ValueError:
            raise Refused('the request does not read')
        if not isinstance(r, dict):
            raise Refused('the request is not an object')
        out['id'] = re.sub(r'[^A-Za-z0-9]', '', str(r.get('id') or ''))[:40]
        if r.get('do') != 'read':
            try:
                at = float(r.get('at') or 0)
            except (TypeError, ValueError):
                at = 0.0
            if abs(time.time() - at) > OTPTLS_FRESH_S:
                raise Refused('that was asked too long ago - ask again on the page')
            out['said'] = otptls_apply(r)
        out['data'] = otptls_read()
        out['ok'] = True
    except Refused as e:
        out['said'] = str(e)[:600]
    except Exception as e:                              # noqa: BLE001 - said, never lost
        out['said'] = 'it went wrong: %s' % str(e)[:300]
    if not out['ok']:
        try:
            out['data'] = otptls_read()
        except Exception:                               # noqa: BLE001
            pass
    write_here(OTPTLS_FILE, json.dumps(out))


def status_read():
    """What this helper wrote last. It lies in the folder the isemon account
    owns, so nothing of it is trusted: what is used again (the DH choice) is
    checked again."""
    try:
        got = json.loads(read_req('status.json').decode('utf-8'))
    except (OSError, ValueError, Refused):
        return {}
    if not isinstance(got, dict):
        return {}
    if got.get('dh') not in DH_CHOICES:
        got['dh'] = 'none'
    return got


def serve():
    d = web_fd()
    try:
        look_part()
    except Exception as e:                              # noqa: BLE001
        print('isemon_web.py: looking: %s' % e, file=sys.stderr)
    try:
        ntp_part()
    except Exception as e:                              # noqa: BLE001
        print('isemon_web.py: the time: %s' % e, file=sys.stderr)
    try:
        net_part()
    except Exception as e:                              # noqa: BLE001
        print('isemon_web.py: the network: %s' % e, file=sys.stderr)
    try:
        sshkeys_part()
    except Exception as e:                              # noqa: BLE001
        print('isemon_web.py: root\'s SSH keys: %s' % e, file=sys.stderr)
    try:
        osup_part()
    except Exception as e:                              # noqa: BLE001
        print('isemon_web.py: the updates of the system: %s' % e, file=sys.stderr)
    try:
        otptls_part()
    except Exception as e:                              # noqa: BLE001
        print('isemon_web.py: the otp logs over TLS: %s' % e, file=sys.stderr)
    # One left by a run that was stopped half way (1.10.238) - a reboot, a
    # timeout during DH: taken away and said, or the daemon would wait on it
    # for ever and never ask again.
    if drop_entry('request.taken'):
        write_here('status.json', json.dumps(dict(status_read(), at=time.time(), state='failed',
                                                  said=['it was stopped half way (the machine '
                                                        'or the service restarted): asked '
                                                        'again'])))
    try:
        os.replace('request.json', 'request.taken', src_dir_fd=d, dst_dir_fd=d)
    except FileNotFoundError:
        return 0
    except OSError:
        drop_entry('request.json')              # a folder in its place
        return 0
    last = status_read()
    out = {'at': time.time(), 'dh': last.get('dh') or 'none'}
    try:
        try:
            raw = json.loads(read_req('request.taken').decode('utf-8'))
        except ValueError as e:
            raise Refused('the request does not read: %s' % e)
        if isinstance(raw, dict):
            out.update(id=re.sub(r'[^A-Za-z0-9]', '', str(raw.get('id') or ''))[:32],
                       hash=re.sub(r'[^0-9a-f]', '', str(raw.get('hash') or ''))[:64])
        PROGRESS['id'] = str(out.get('id') or '')
        progress('checking what was asked', 1)
        r = checked(raw)
        out.update(id=r['id'], hash=r['hash'])
        fw_can(r['fw'])
        said_n, dh = nginx_part(r, last)
        out['dh'] = dh
        try:
            said_f, fw = fw_part(r['fw'])
        except Refused as e:
            # nginx's half is in force by now: said, beside why the
            # firewall's half is not, rather than as if nothing were.
            raise Refused('; '.join([s for s in said_n if s] + [str(e)]))
        out.update(state='done', said=[s for s in said_n + said_f if s], fw=fw)
    except Refused as e:
        out.update(state='failed', said=[str(e)])
    except Exception as e:                              # noqa: BLE001 - said, never lost
        out.update(state='failed', said=['it broke: %s' % e])
    finally:
        for name in ('request.taken', 'progress.json'):
            drop_entry(name)
    write_here('status.json', json.dumps(out))
    try:
        write_here(LOOK_FILE, json.dumps(look()))
    except Exception:                                   # noqa: BLE001
        pass
    return 0


def main(argv):
    if argv[:1] == ['--status']:
        print(json.dumps({'status': status_read(), 'look': look()}, indent=1))
        return 0
    if os.geteuid() != 0 and not NO_SERVICES:
        print('isemon_web.py: root only', file=sys.stderr)
        return 2
    # The update of the system, started by osup_part as a unit of its own.
    if argv[:1] == ['--os-job'] and len(argv) >= 3 and argv[2] in ('check', 'upgrade'):
        return osup_job(re.sub(r'[^A-Za-z0-9]', '', argv[1])[:40], argv[2],
                        argv[3:4] == ['security'])
    return serve()


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
