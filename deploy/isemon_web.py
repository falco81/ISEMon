#!/usr/bin/python3 -I
"""isemon_web.py - the parts of the web server and the firewall that need
root, put in place by root (isemon 1.10.222; after otp's otp_web.py).

Three things Settings may ask for that the daemon - which runs as `isemon`
and may not write a byte of /etc - cannot do itself:

  * who may reach which page: the dashboard, the published ban list
    (banfeed.php) and the health check (healthz.php), each as its own list
    of addresses and networks in /etc/nginx/conf.d/isemon.conf;
  * TLS: the certificate (with its chain, and the root it is checked
    against), the protocols, the ciphers, the DH parameters and HSTS;
  * the machine's firewall: a chain of isemon's own, ISEMON-IN, first in
    INPUT, for IPv4 and IPv6 - what isemon needs let in by itself, and the
    rules of the site's own.

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

  isemon_web.py            serve request.json and look.ask (as root, from systemd)
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
        with os.fdopen(fd, 'w') as f:
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
    return out


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


def nginx_part(r, last):
    """The server's TLS and lists, as asked. Returns (words, dh made)."""
    said, dh = [], (last.get('dh') or 'none')
    t = r['tls']
    dh_path = None
    if t:
        # DH parameters made first: it can take minutes, and nginx's file is
        # read only after it, so nothing changed in it meanwhile is written
        # over with an older copy.
        dh_path = dh_file(t['dh'], TLS_FILES['dh'], last.get('dh'))
        dh = t['dh']
    paths = [NGINX_MAIN] + list(TLS_FILES.values())
    snap = snapshot(paths)
    changed = False
    try:
        try:
            with open(NGINX_MAIN) as f:
                main = f.read()
        except OSError as e:
            raise Refused('the dashboard\'s nginx file cannot be read (%s): %s' % (NGINX_MAIN, e))
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
        elif t and t['pem']:
            changed = True          # the same lines, new files: nginx reads them again
        if changed and not NO_SERVICES:
            progress('asking nginx, and reloading it', 4)
            got = subprocess.run(['nginx', '-t'], capture_output=True, text=True)
            if got.returncode != 0:
                raise Refused('nginx does not take it, so it is as it was: %s'
                              % ((got.stderr or '').strip().splitlines() or ['?'])[-1][:300])
            subprocess.run(['systemctl', 'reload', 'nginx'], capture_output=True)
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
    last_decl = max([i for i in range(start, end) if rows[i].startswith(':')] or [start])
    first_input = next((i for i in range(start, end) if rows[i].startswith('-A INPUT')), end)
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


def look_part():
    d = web_fd()
    try:
        os.unlink(LOOK_ASK, dir_fd=d)
    except FileNotFoundError:
        return
    try:
        out = look()
    except Exception as e:                              # noqa: BLE001 - said, never lost
        out = {'at': time.time(), 'said': 'it could not be read: %s' % str(e)[:200]}
    write_here(LOOK_FILE, json.dumps(out))


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
        os.replace('request.json', 'request.taken', src_dir_fd=d, dst_dir_fd=d)
    except FileNotFoundError:
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
        said_n, dh = nginx_part(r, last)
        out['dh'] = dh
        said_f, fw = fw_part(r['fw'])
        out.update(state='done', said=[s for s in said_n + said_f if s], fw=fw)
    except Refused as e:
        out.update(state='failed', said=[str(e)])
    except Exception as e:                              # noqa: BLE001 - said, never lost
        out.update(state='failed', said=['it broke: %s' % e])
    finally:
        for name in ('request.taken', 'progress.json'):
            try:
                os.unlink(name, dir_fd=d)
            except OSError:
                pass
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
    return serve()


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
