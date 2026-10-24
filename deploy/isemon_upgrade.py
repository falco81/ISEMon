#!/usr/bin/python3 -I
"""isemon_upgrade.py - a new version of isemon, put in by root (isemon 1.10.222;
after otp's otp_upgrade.py).

The pages cannot upgrade anything themselves: the service runs as `isemon`,
which may not write a byte of the program. What it may do is lay a package
down in /var/lib/isemon/upgrade/ and ask for it with request.json; systemd
(isemon-upgrade.path) sees the request and starts isemon-upgrade.service, which
runs this as root. This then trusts nothing it was handed:

  * the package is copied to a folder of root's own before anything is read
    from it, so it cannot be changed under the check;
  * it must be signed: MANIFEST lists the SHA-256 of every file, and
    MANIFEST.sig is the Ed25519 signature of MANIFEST by one of the keys in
    /usr/local/lib/isemon/release-keys/ - which only root can write, and which
    only a package installed by root (install.sh, or this) puts there;
  * every file in it is listed in MANIFEST with the right hash, nothing more,
    no links, no device, no path outside its one folder;
  * it is not older than the version installed (the same one again is a
    retry and is allowed).

Then its own install.sh --upgrade --yes is run, exactly as somebody would
on the command line, and what it said is written back for the pages.

  isemon_upgrade.py                 serve request.json (as root, from systemd)
  isemon_upgrade.py --inspect FILE  check a package and say what it is (JSON);
                                 any user - the daemon asks this way
  isemon_upgrade.py --run FILE      check and put in a package by hand (root)
"""
import hashlib
import json
import os
import re
import shutil
import stat
import signal
import subprocess
import threading
import sys
import tarfile
import tempfile
import time

STATE_DIR = os.environ.get('ISEMON_STATE', '/var/lib/isemon')
UPGRADE_DIR = os.path.join(STATE_DIR, 'upgrade')
LIB_DIR = os.environ.get('ISEMON_LIB', '/usr/local/lib/isemon')
KEYS_DIR = os.environ.get('ISEMON_RELEASE_KEYS', os.path.join(LIB_DIR, 'release-keys'))
MOST_PACKED = 64 * 1024 * 1024
MOST_UNPACKED = 256 * 1024 * 1024
MOST_FILES = 5000
INSTALL_LIMIT_S = 20 * 60      # under TimeoutStartSec=25min and the daemon's 30 (1.0.59)
SERVICE_USER = os.environ.get('ISEMON_USER', 'isemon')
TOP = re.compile(r'^isemon-([0-9]+(?:\.[0-9]+){2,3})$')


class Refused(Exception):
    pass


# The upgrade folder, opened once and used by its descriptor from then on
# (otp 1.0.44): the isemon account owns /var/lib/isemon, and could otherwise swap the
# folder for a link to anywhere between two steps of root's.
UP_FD = [None]


def up_fd():
    if UP_FD[0] is not None:
        return UP_FD[0]
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    top = os.open(STATE_DIR, flags)
    try:
        fd = os.open('upgrade', flags, dir_fd=top)
    finally:
        os.close(top)
    st = os.fstat(fd)
    try:
        import pwd
        want = pwd.getpwnam(SERVICE_USER).pw_uid
    except (KeyError, ImportError):
        want = st.st_uid
    if st.st_uid not in (0, want):
        os.close(fd)
        raise Refused('%s is owned by uid %d, not by %s' % (UPGRADE_DIR, st.st_uid, SERVICE_USER))
    UP_FD[0] = fd
    return fd


def _where(path):
    """(dir_fd, name) for a path in the upgrade folder, (None, path) else."""
    if os.path.dirname(path) == UPGRADE_DIR:
        return up_fd(), os.path.basename(path)
    return None, path


def version_tuple(v):
    return tuple(int(x) for x in str(v).split('.'))


def installed_version():
    try:
        with open(os.path.join(LIB_DIR, 'isemon.py'), encoding='utf-8') as f:
            for line in f:
                m = re.match(r"^__version__ = '([0-9.]+)'", line)
                if m:
                    return m.group(1)
    except OSError:
        pass
    return ''


def trusted_keys():
    try:
        names = sorted(n for n in os.listdir(KEYS_DIR) if n.endswith('.pub'))
    except OSError:
        names = []
    return [os.path.join(KEYS_DIR, n) for n in names]


def signed_by(manifest, signature):
    """The name of the trusted key that signed MANIFEST, or None."""
    for key in trusted_keys():
        try:
            r = subprocess.run(['openssl', 'pkeyutl', '-verify', '-pubin', '-inkey', key,
                                '-rawin', '-in', manifest, '-sigfile', signature],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        except (OSError, subprocess.SubprocessError):
            raise Refused('openssl is needed to check the signature, and it did not run')
        if r.returncode == 0:
            return os.path.basename(key)[:-4]
    return None


def inspect(path, extract_to=None):
    """Everything about a package that can be said without trusting it - and
    with extract_to, the package unpacked there once it has passed."""
    try:
        size = os.path.getsize(path)
    except OSError as e:
        raise Refused('the package cannot be read: %s' % e)
    if size > MOST_PACKED:
        raise Refused('the package is bigger than 64 MB, which no version of isemon is')
    try:
        tar = tarfile.open(path, 'r:gz')
    except (tarfile.TarError, OSError, EOFError) as e:
        raise Refused('that is not a .tar.gz: %s' % e)
    with tar:
        # Read one header at a time and stopped at the limit (1.0.44):
        # getmembers() read every header first, millions of them if the
        # package said so, before anything was counted.
        members = []
        try:
            while True:
                one = tar.next()
                if one is None:
                    break
                members.append(one)
                if len(members) > MOST_FILES:
                    break
        except (tarfile.TarError, OSError, EOFError) as e:
            raise Refused('the package is damaged: %s' % e)
        if not members or len(members) > MOST_FILES:
            raise Refused('the package holds no files, or far too many')
        top = members[0].name.split('/')[0]
        m = TOP.match(top)
        if not m:
            raise Refused('the package is not an isemon release: its folder is "%s", not isemon-X.Y.Z'
                          % top[:80])
        version = m.group(1)
        files, total = {}, 0
        for one in members:
            name = one.name
            parts = name.split('/')
            if name.startswith('/') or '..' in parts or parts[0] != top or '\\' in name:
                raise Refused('the package has a path outside its folder: %s' % name[:120])
            if one.isdir():
                continue
            if not one.isreg():
                raise Refused('the package holds something that is not a plain file: %s'
                              % name[:120])
            total += one.size
            if total > MOST_UNPACKED:
                raise Refused('the package unpacks to more than 256 MB')
            rel = '/'.join(parts[1:])
            if rel in files:
                raise Refused('the package holds %s twice' % rel)
            files[rel] = one
        for need in ('MANIFEST', 'MANIFEST.sig', 'isemon.py', 'install.sh'):
            if need not in files:
                raise Refused('the package has no %s%s' % (need, ' - it is not signed'
                                                             if need.startswith('MANIFEST')
                                                             else ''))
        work = tempfile.mkdtemp(prefix='isemon-inspect-')
        try:
            man = os.path.join(work, 'MANIFEST')
            sig = os.path.join(work, 'MANIFEST.sig')
            for rel, dest in (('MANIFEST', man), ('MANIFEST.sig', sig)):
                if files[rel].size > 4 * 1024 * 1024:
                    raise Refused('%s is far too big' % rel)
                with tar.extractfile(files[rel]) as src, open(dest, 'wb') as out:
                    out.write(src.read())
            if not trusted_keys():
                raise Refused('no release key is installed on this machine (%s): upgrade once '
                              'on the command line with install.sh --upgrade' % KEYS_DIR)
            who = signed_by(man, sig)
            if not who:
                raise Refused('the signature is not by any release key this machine trusts - '
                              'a package that was changed, or signed by an unknown key. Put it '
                              'in on the command line (install.sh --upgrade) if you trust it.')
            listed = {}
            with open(man, encoding='utf-8') as f:
                for line in f:
                    line = line.rstrip('\n')
                    if not line.strip():
                        continue
                    mm = re.match(r'^([0-9a-f]{64})  (.+)$', line)
                    if not mm:
                        raise Refused('MANIFEST has a line that does not read')
                    listed[mm.group(2)] = mm.group(1)
            have = set(files) - {'MANIFEST', 'MANIFEST.sig'}
            if set(listed) != have:
                extra = sorted(have - set(listed))[:3]
                missing = sorted(set(listed) - have)[:3]
                raise Refused('the files are not the ones signed for%s%s' % (
                    (' - not signed: ' + ', '.join(extra)) if extra else '',
                    (' - missing: ' + ', '.join(missing)) if missing else ''))
            changelog = ''
            isemon_version = ''
            for rel in sorted(have):
                h = hashlib.sha256()
                keep = rel in ('CHANGELOG.md', 'isemon.py', 'README.md')
                body = []
                with tar.extractfile(files[rel]) as src:
                    while True:
                        lump = src.read(1 << 20)
                        if not lump:
                            break
                        h.update(lump)
                        if keep:
                            body.append(lump)
                if h.hexdigest() != listed[rel]:
                    raise Refused('%s is not the file that was signed' % rel)
                if rel == 'isemon.py':
                    mm = re.search(rb"^__version__ = '([0-9.]+)'", b''.join(body), re.M)
                    isemon_version = mm.group(1).decode() if mm else ''
                if rel == 'README.md' and not changelog:
                    # isemon says what changed under "## Version" in its
                    # README: the version on a line of its own, then what
                    # changed, until the next version.
                    text = b''.join(body).decode('utf-8', 'replace')
                    mm = re.search(r'(?ms)^%s\n(.*?)(?=^[0-9]+\.[0-9]+\.[0-9]+\s*$|\Z)'
                                   % re.escape(version), text)
                    changelog = mm.group(1).strip()[:20000] if mm else ''
                if rel == 'CHANGELOG.md':
                    text = b''.join(body).decode('utf-8', 'replace')
                    mm = re.search(r'^## %s\b.*?(?=^## |\Z)' % re.escape(version), text,
                                   re.M | re.S)
                    changelog = mm.group(0).strip()[:20000] if mm else ''
            if isemon_version != version:
                raise Refused('the folder says %s and isemon.py says %s' % (version, isemon_version))
            if extract_to:
                for one in members:
                    target = os.path.join(extract_to, one.name)
                    if one.isdir():
                        os.makedirs(target, mode=0o755, exist_ok=True)
                        continue
                    os.makedirs(os.path.dirname(target), mode=0o755, exist_ok=True)
                    with tar.extractfile(one) as src, \
                            open(target, 'xb') as out:
                        shutil.copyfileobj(src, out)
                    os.chmod(target, 0o755 if one.mode & 0o111 else 0o644)
        finally:
            shutil.rmtree(work, ignore_errors=True)
    have_v = installed_version()
    return {'version': version, 'top': top, 'files': len(have), 'signed_by': who,
            'bytes': size, 'changelog': changelog, 'installed': have_v,
            'newer': not have_v or version_tuple(version) > version_tuple(have_v),
            'older': bool(have_v) and version_tuple(version) < version_tuple(have_v)}


# ---- writing where isemon may also write: never through a link ----------------------
def write_safely(path, data, mode=0o640):
    """`data` into `path`, in a folder the isemon account owns: a new file made
    beside it and renamed over it, so a link put there in its place is
    replaced, never followed."""
    dfd, name = _where(path)
    folder = os.path.dirname(path)
    for _ in range(20):
        tmpname = '.%s.%d.%d' % (os.path.basename(path), os.getpid(),
                                 int(time.time() * 1e6) % 10 ** 9)
        tmp = tmpname if dfd is not None else os.path.join(folder, tmpname)
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode,
                         dir_fd=dfd)
        except FileExistsError:
            continue
        with os.fdopen(fd, 'wb') as out:
            out.write(data if isinstance(data, bytes) else data.encode('utf-8'))
            try:
                os.fchown(out.fileno(), 0, _service_gid())
            except (OSError, KeyError):
                pass
        os.replace(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
        return
    raise OSError('could not write %s' % path)


def _service_gid():
    import grp
    return grp.getgrnam(SERVICE_USER).gr_gid


def read_small(path, most=65536):
    dfd, name = _where(path)
    # O_NONBLOCK: a FIFO put in its place does not hold root up (1.0.44).
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise Refused('%s is not a file' % path)
    with os.fdopen(fd, 'rb') as f:
        return f.read(most + 1)[:most]


def status(**fields):
    fields['at'] = time.time()
    write_safely(os.path.join(UPGRADE_DIR, 'status.json'), json.dumps(fields))


def put_in(package, ident='', want_sha='', by='the command line', log_to=None):
    """Check the package and run its install.sh --upgrade. Returns (rc, log)."""
    if os.geteuid() != 0:
        raise Refused('putting a version in takes root')
    work = tempfile.mkdtemp(prefix='isemon-upgrade-', dir='/var/tmp')
    os.chmod(work, 0o700)
    lines = []

    def say(text):
        lines.append(text)
        if log_to:
            log_to(text)
    try:
        copy = os.path.join(work, 'package.tar.gz')
        pfd, pname = _where(package)
        fd = os.open(pname, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=pfd)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            raise Refused('the package is not a plain file')
        with os.fdopen(fd, 'rb') as src, open(copy, 'xb') as out:
            n = 0
            h = hashlib.sha256()
            while True:
                lump = src.read(1 << 20)
                if not lump:
                    break
                n += len(lump)
                if n > MOST_PACKED:
                    raise Refused('the package is bigger than 64 MB')
                h.update(lump)
                out.write(lump)
        if want_sha and h.hexdigest() != want_sha:
            raise Refused('the package is not the one that was checked on the pages '
                          '(its SHA-256 differs)')
        unpacked = os.path.join(work, 'x')
        os.makedirs(unpacked, mode=0o700)
        info = inspect(copy, extract_to=unpacked)
        if info['older']:
            raise Refused('%s is older than %s, which is installed: going back is done on the '
                          'command line' % (info['version'], info['installed']))
        say('isemon %s, signed by %s, %d files - checked' % (info['version'], info['signed_by'],
                                                         info['files']))
        src = os.path.join(unpacked, info['top'])
        env = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
               'LANG': 'C.UTF-8', 'ISEMON_UPGRADE_FROM_PAGES': '1', 'TERM': 'dumb',
               'ISEMON_UPGRADE_BY': str(by)[:100]}
        say('running %s/install.sh --upgrade --yes' % info['top'])
        p = subprocess.Popen(['bash', os.path.join(src, 'install.sh'), '--upgrade', '--yes'],
                             cwd=src, env=env, stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        # A deadline of its own (1.0.59), under systemd's and the daemon's:
        # an install.sh that hangs (a dnf lock, a slow mirror) is stopped
        # here and said failed, not killed with the status left "running".
        late = []

        def too_long():
            late.append(1)
            try:
                p.kill()
            except OSError:
                pass
        dog = threading.Timer(INSTALL_LIMIT_S, too_long)
        dog.daemon = True
        dog.start()

        def stopped(_sig, _frame):
            too_long()
            raise Refused('isemon-upgrade.service was stopped while install.sh ran')
        signal.signal(signal.SIGTERM, stopped)
        try:
            for raw in p.stdout:
                say(re.sub(r'\x1b\[[0-9;]*m', '', raw.decode('utf-8', 'replace').rstrip('\n')))
            rc = p.wait()
        finally:
            dog.cancel()
            signal.signal(signal.SIGTERM, signal.SIG_DFL)
        if late:
            raise Refused('install.sh did not finish in %d min and was stopped'
                          % (INSTALL_LIMIT_S // 60))
        say('install.sh ended with %d' % rc)
        return rc, info, lines
    finally:
        shutil.rmtree(work, ignore_errors=True)


def serve_request():
    """What systemd starts when request.json appears."""
    req = os.path.join(UPGRADE_DIR, 'request.json')
    taken = os.path.join(UPGRADE_DIR, 'request.taken')
    try:
        dfd = up_fd()
        os.replace('request.json', 'request.taken', src_dir_fd=dfd, dst_dir_fd=dfd)
    except FileNotFoundError:
        return 0
    ident = ''
    log_path = os.path.join(UPGRADE_DIR, 'last.log')
    log_lines = []
    last_flush = [0.0]
    # How far it is, for the bar on the page (1.10.222): checking the
    # package is the first tenth, install.sh's own steps the rest - it says
    # each one as `@@progress N/T words` when it is run from here.
    run = {'id': '', 'version': '', 'step': 0, 'total': 0, 'words': 'checking the package',
           'pct': 2, 'began': time.time()}

    def say_status(state='running', **more):
        status(id=run['id'], state=state, version=run['version'], pid=os.getpid(),
               progress={'pct': run['pct'], 'words': run['words'], 'step': run['step'],
                         'total': run['total'], 'began': run['began']}, **more)

    def log_to(text):
        m = re.match(r'^@@progress ([0-9]{1,3})/([0-9]{1,3}) (.{0,120})$', text.strip())
        if m:
            n, t = int(m.group(1)), max(1, int(m.group(2)))
            run.update(step=n, total=t, words=m.group(3).strip(),
                       pct=min(97, 10 + int(85 * min(n, t) / t)))
            try:
                say_status()
            except OSError:
                pass
            return
        if text.startswith('running ') and text.endswith('--upgrade --yes'):
            run.update(words='install.sh is starting', pct=10)
            try:
                say_status()
            except OSError:
                pass
        log_lines.append(text)
        if time.time() - last_flush[0] > 2:
            last_flush[0] = time.time()
            try:
                write_safely(log_path, '\n'.join(log_lines[-4000:]) + '\n')
            except OSError:
                pass
    try:
        try:
            r = json.loads(read_small(taken).decode('utf-8'))
        except (ValueError, OSError) as e:
            raise Refused('the request does not read: %s' % e)
        ident = str(r.get('id') or '')[:64]
        run['id'] = ident
        name = os.path.basename(str(r.get('file') or ''))
        if not re.match(r'^isemon-[0-9.]+\.tar\.gz$', name):
            raise Refused('the request names no package')
        run.update(id=ident, version=str(r.get('version') or '')[:20])
        say_status()
        rc, info, _ = put_in(os.path.join(UPGRADE_DIR, name), ident,
                             str(r.get('sha') or ''), r.get('by') or 'the pages', log_to)
        run.update(version=info['version'], pct=100 if rc == 0 else run['pct'],
                   words='done' if rc == 0 else 'install.sh ended with %d' % rc)
        say_status('done' if rc == 0 else 'failed', rc=rc, tail=log_lines[-40:])
    except Refused as e:
        log_to('refused: %s' % e)
        run['words'] = 'refused'
        say_status('failed', rc=-1, said=str(e), tail=log_lines[-40:])
    except Exception as e:                       # noqa: BLE001 - said, never lost
        log_to('broke: %s' % e)
        run['words'] = 'broke'
        say_status('failed', rc=-2, said='the upgrade broke: %s' % e, tail=log_lines[-40:])
    finally:
        last_flush[0] = 0
        try:
            write_safely(log_path, '\n'.join(log_lines[-4000:]) + '\n')
        except OSError:
            pass
        try:
            os.unlink('request.taken', dir_fd=up_fd())
        except (OSError, Refused):
            pass
    return 0


def main(argv):
    if len(argv) >= 2 and argv[0] == '--inspect':
        try:
            print(json.dumps(dict(inspect(argv[1]), ok=True)))
        except Refused as e:
            print(json.dumps({'ok': False, 'said': str(e)}))
        return 0
    if len(argv) >= 2 and argv[0] == '--run':
        try:
            rc, _info, _ = put_in(os.path.abspath(argv[1]), log_to=print)
        except Refused as e:
            print('refused: %s' % e)
            return 1
        return rc
    if not argv:
        return serve_request()
    print(__doc__)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
