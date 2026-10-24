# php2shell (CVE-2026-109618, CVE-2026-109619) on an isemon server

What php2shell is, what isemon does about it, and the whole procedure for an
AlmaLinux 9 (or Rocky / RHEL 9) server running the isemon dashboard - from
the first look at what is installed to checking that the fixed PHP is the one
running.

## 1. What it is

On 21 October 2026 PHP released fixes for two critical remote code execution
flaws, together called **php2shell**:

| CVE | What goes wrong |
|---|---|
| CVE-2026-109618 | PHP's out-of-memory handling while a request is being set up leaves data half-initialised; cleaning it up leads to code execution. |
| CVE-2026-109619 | Request state (session upload progress) is kept after its memory is freed; the next request in the same worker can use it - use-after-free, code execution. |

Both are **unauthenticated** and are reached through how PHP takes a request's
body apart - a `multipart/form-data` body and its upload progress - *before a
single line of the page runs*. Nothing the application itself checks can stop
them. Every web SAPI is affected: php-fpm, mod_php, php-cgi.

Fixed upstream releases: **8.2.35, 8.3.36, 8.4.27, 8.5.12**. PHP 8.1 and older
are end of life and get no fix from PHP itself.

**Updating PHP is the only fix.** Everything else below keeps the dashboard
out of the way of the flaws until the update is installed.

## 2. What isemon does (1.10.218 and later)

- **The dashboard never needs PHP to take a body apart.** Everything it sends
  is JSON; a database put back (*Settings → The database*) is sent as the file
  itself (`application/octet-stream`), read from `php://input` and written down
  as it arrives. No page of isemon sends or reads a multipart form.
- **nginx refuses every multipart body** with 403 (any letter case), so one
  never reaches PHP at all. This is the guard that matters most while PHP is
  not fixed.
- **`web/.user.ini`** switches PHP's own body parsing and upload progress off
  for the dashboard's directory (`enable_post_data_reading = Off`,
  `session.upload_progress.enabled = 0`, `session.use_strict_mode = 1`). Note:
  a per-directory `.user.ini` is applied late in the request, so on its own it
  is **not** a sufficient guard - set the same thing for the whole of PHP
  (step 4 below).
- **The installer** (`./install.sh --upgrade`) puts the multipart rule into an
  existing nginx vhost - the only change an upgrade makes to it - keeping the
  previous file beside it as `isemon.conf.before-php2shell`, checking it with
  `nginx -t`, and putting it back if nginx will not read it. It also says
  whether the PHP it finds has the fix.
- **The dashboard** tells an administrator, in its header, while the PHP
  running the page has a version below the fixed ones (red when the page's
  own guard is not in force either, amber when it is).

## 3. See what is installed

```bash
rpm -qa 'php*' | sort
dnf module list --enabled php
php -v
```

On AlmaLinux 9 the default PHP is 8.0 (`php-*-8.0.30-*.el9_*`). AlmaLinux
backports the fix into its own packages - the default 8.0 and the `php:8.2`
and `php:8.3` module streams - so **the fixed package keeps its old version
number** (8.0.30, 8.2.33 ...). Do not wait for a package called 8.2.35; look
for the CVE in its errata and changelog (step 7).

## 4. Guard PHP as a whole, now

Upload progress off for every PHP on the machine, and sessions strict - in
`/etc/php.d`, which php-fpm reads at start, early enough:

```bash
printf 'session.upload_progress.enabled = 0\nsession.use_strict_mode = 1\n' \
    > /etc/php.d/99-php2shell.ini
systemctl restart php-fpm
php -i | grep -E 'upload_progress.enabled|use_strict_mode'
```

Expected:

```
session.upload_progress.enabled => Off => Off
session.use_strict_mode => On => On
```

isemon does not use PHP sessions or upload progress, so this costs it nothing.

(AlmaLinux also suggests a small `post_max_size` against CVE-2026-109618. On
an isemon server that would refuse putting a database copy back, which is
sent through the page; the nginx rule below already keeps multipart bodies
away from PHP, so leave `post_max_size` as it is.)

## 5. Upgrade isemon and check nginx refuses multipart

```bash
tar xzf isemon-1.10.219.tar.gz
cd isemon-1.10.219
sudo ./install.sh --upgrade
```

Then, on the server:

```bash
curl -k -o /dev/null -s -w '%{http_code}\n' https://localhost/index.php            # 200
curl -k -o /dev/null -s -w '%{http_code}\n' -F a=b https://localhost/index.php     # 403
grep -n multipart /etc/nginx/conf.d/isemon.conf
```

The first must be **200** and the second **403**, and `grep` must show the
rule:

```
if ($http_content_type ~* "multipart") { return 403; }
```

If the first one is not 200 either, `localhost` reached another server block;
use the dashboard's own name:

```bash
curl -k --resolve isemon.example.com:443:127.0.0.1 -o /dev/null -s -w '%{http_code}\n' \
    -F a=b https://isemon.example.com/index.php
```

If the installer could not put the rule in, it said so and printed the line
to add inside the vhost's `server { }` block; add it, then
`nginx -t && systemctl reload nginx`.

## 6. Optional: move to a newer PHP stream

The default 8.0 gets the fix too, so this is not needed for php2shell. To move
to 8.2 anyway (isemon needs only `php-cli`, `php-common` and `php-fpm`):

```bash
dnf module reset -y php
dnf module enable -y php:8.2
dnf distro-sync -y 'php*'
systemctl restart php-fpm
php -v
```

Moving to a stream does not by itself install the fix - the stream's fixed
build may not be out yet (on 21 October 8.2 was still 8.2.33). After moving:

```bash
php -i | grep -E 'upload_progress.enabled|use_strict_mode'   # the guard from step 4 still applies
ls /etc/php-fpm.d/*.rpmnew /etc/php.ini.rpmnew 2>/dev/null   # nothing: your configuration was kept
```

Then sign in to the dashboard and open a few pages, to see php-fpm on the new
version serves it (and still reaches the daemon's token).

## 7. Install the fixed PHP when it is out

AlmaLinux publishes the fixed packages first to its testing repository, then
to the regular ones; its announcement says which versions and how to get them
from testing early:
<https://almalinux.org/blog/2026-10-21-php2shell-cve-2026-109618-cve-2026-109619/>

When they are out:

```bash
dnf upgrade --refresh 'php*'
systemctl restart php-fpm
```

Check that the fix is installed - by the CVE, not by the version number:

```bash
dnf updateinfo list --cve CVE-2026-109618
dnf updateinfo list --cve CVE-2026-109619
rpm -q --changelog php-fpm | head -5
```

And that php-fpm is running the new build, not the old one still in memory:

```bash
grep -lE ' /(usr|lib|opt).*\(deleted\)$' /proc/[0-9]*/maps
```

No output means every process runs the new files. If it lists PIDs, restart
php-fpm again and repeat.

## 8. After the fix

- The dashboard's header warning compares the **version number** only. With a
  backported fix (8.0.30, 8.2.33 ...) it can stay after the update even though
  the fix is installed - what `dnf updateinfo` says in step 7 is what counts.
  Once it does, `isemon --php-notice hide` puts the notice away until the
  daemon starts again (nothing is saved, so a restart shows it again while
  the version is below the fixed ones); `isemon --php-notice show` brings it
  back.
- Keep the nginx multipart rule and `/etc/php.d/99-php2shell.ini`: isemon does
  not need multipart bodies or upload progress, so both cost nothing and stay
  as a second layer.
- If you ever need to remove the nginx rule, the vhost as it was before is
  `/etc/nginx/conf.d/isemon.conf.before-php2shell`.

## 9. Was it attacked before it was guarded?

php2shell runs code as the web worker's account (`apache` on AlmaLinux). Signs
to look for:

```bash
# multipart requests that reached PHP before the rule (status other than 403)
grep -E 'POST [^ ]*\.php' /var/log/nginx/isemon-access.log | grep -v '" 403 '
# php-fpm workers that started a shell or a downloader
ps -eo pid,ppid,user,args --forest | grep -A3 php-fpm
# files changed in the web root, new cron jobs, new accounts
find /var/www/isemon -newer /var/www/isemon/index.php -type f
ls -la /var/spool/cron /etc/cron.d
tail -20 /etc/passwd
```

Anything unexpected - a shell or `curl`/`wget` started by php-fpm, a file in
the web root that is not isemon's, a new cron job - means the machine should
be treated as compromised.

## Sources

- AlmaLinux: <https://almalinux.org/blog/2026-10-21-php2shell-cve-2026-109618-cve-2026-109619/>
- Applying the patches: <https://ma.ttias.be/php-cve-2026-109618-patch/>
- Early mitigation steps: <https://ma.ttias.be/php-cve-2026-109618-early-mitigation/>
- Tenable FAQ: <https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-frequently-asked-questions-about-critical-php-remote>
- Huntress: <https://www.huntress.com/blog/php2shell-leaked-critical-php-vulnerabilities>
