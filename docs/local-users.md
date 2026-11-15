# Local users

*Settings → Local users* (full administrators only, 1.10.351): the users of
this server's own system - who may sign in to the machine itself, over SSH or
at its console. They are not the accounts of these pages (*Accounts*). It
follows acme's page of the same name (1.0.243) and its password policy
(1.0.43), for one server: there is one node, this machine.

Root's helper (`isemon_web.py`, started by `isemon-web.path` when the daemon
lays `/var/lib/isemon/web/users.ask` down) does every change with the
system's own tools - `useradd`, `usermod`, `chpasswd -e`, `chage`, `gpasswd`,
`userdel` - each run from a list of words, never through a shell, exactly as
an administrator would at the console. It answers in `users.json`.

## What is shown

One row a user. The accounts in the normal range with no shell (often a
package's) are hidden until *Also the N accounts with no shell* is switched
on. A user's pencil opens the facts - UID, home folder, shell, groups, the
password (none / set on a day / to be changed at the next sign-in), when it
runs out, locked or not, sudo.

**root** is first and **shown only**: its password, its shell and whether it
may sign in are changed on the machine itself, never from isemon - the API
and root's helper refuse any change of it. Accounts of the system (outside
`UID_MIN`..`UID_MAX` of `/etc/login.defs`) and the services' own are neither
shown nor changed, whatever their UID: `isemon`, nginx, apache / php-fpm's,
`www-data`, postgres, mysql / mariadb, nobody, chrony, sshd, polkitd, dbus,
systemd-network, systemd-resolve, tss, keepalived, rsyslog's (`syslog`), sssd
and freeradius's.

## What can be done

| | |
|---|---|
| **Add a user** | name, full name, shell (from `/etc/shells`), a password (or none: SSH keys only), *to be changed at the first sign-in*, sudo; the lowest UID of the normal range nobody uses |
| **Name and shell** | the full name (GECOS) and the shell |
| **Password** | a new one, typed twice; *to be changed at the next sign-in* if wanted |
| **Password aging** | good for (days), warned so many days before, the least days between two changes (`chage -M -W -m`) |
| **Give / take sudo** | membership of `wheel` (RHEL) or `sudo` (Debian, Ubuntu) - root with their own password |
| **Lock / unlock** | locked: the password put out of use (`usermod -L`) *and* the account ended (`chage -E 0`) - no SSH key lets them in either, since sshd asks PAM's account step; nothing of theirs is taken away. The day the account was set to end before is kept in a file of root's (`/var/lib/isemon-root/users-expiry.json`) and put back by Unlock while it is still ahead |
| **Take the user away** | `userdel`, with the home folder or without; refused while they are signed in or run something (`pgrep -u UID`) |

A user with no password at all is not *locked*: a key lets them in. A user
made with no password gets no aging (`chage -M -1 -I -1`) - sshd's account step
would otherwise ask a key's user for a new password they have no old one to
give for. Adding a user with sudo and no password is refused: sudo asks for
their own password.

The SSH keys of a user are in *Settings → SSH keys* (*Whose keys*) once the
user is there.

## The password

Typed on the page, it never leaves the daemon as itself:

1. its length is checked (8 to 256, no control characters), then the password
   policy (by `pwscore` where it is installed, else the rules set here);
2. the daemon makes its hash - SHA-512 crypt, `openssl passwd -6 -stdin`, the
   password on standard input, never on a command line;
3. the hash goes to root's helper in the ask file only - in isemon's own
   folder, 0600, taken away by the helper as soon as it is read, or by the
   daemon when root does not answer in time;
4. the helper checks the hash's shape before it does anything at all, and
   hands `NAME:HASH` to `chpasswd -e` on its standard input.

The password and its hash are in no row of the database, no log and no event.
Events say who changed which user, and how - never the password.

## The password policy

The card **Password policy**: one policy for the local users, put in by root's
helper into the system's own files - so it holds however a password is
changed (`passwd`, a password run out at sign-in, these pages). **Off by
default**: the system as it is, nothing written. Switched off again, every
file is put back as it was, byte for byte.

| Rule | Where it goes |
|---|---|
| characters at least, kinds, the same character in a row, characters not in the old one, no word of the dictionary, not the user's name (`retry = 3`) | `/etc/security/pwquality.conf.d/50-isemon.conf` (a drop-in; `pwquality.conf` itself untouched) |
| the last N passwords not taken again | `/etc/security/pwhistory.conf`, isemon's lines between marks |
| locked after N wrong, for how long, counted within | `/etc/security/faillock.conf`, isemon's lines between marks - `even_deny_root` never: root is never locked |
| good for, warned before, the least days between two changes | `/etc/login.defs` (`PASS_MAX_DAYS`, `PASS_MIN_DAYS`, `PASS_WARN_AGE`); what it had is kept in it, commented between isemon's marks (`# isemon-was: …`) |

The marks are `# ---- isemon: Settings -> Local users -> Password policy (from
here) ----` and `# ---- isemon: (to here) ----`; the rest of each file stays
as it was, a link is refused, and a file is written only when its text
changes. With **authselect** (RHEL), `with-pwhistory` and `with-faillock` are
switched on where needed - and off again, only those isemon switched on (kept
in `/var/lib/isemon-root/pwpolicy-orig.json`). *Also for the users there now*
puts the days (`chage -M -m -W`) on every normal user with a password; users
with no password (a key only) are left without. root is never aged.

The policy is a setting of the daemon (`osu_pwpolicy`); the daemon puts it in
when it was saved, after it starts, and again ten minutes after root refused
it. *In effect* shows what the machine has, read from its files and PAM.

## The API

`GET /api/osusers` - acme's shape, `"cluster": false`, one node:

```json
{"ok": true, "cluster": false, "pw_min": 8, "openssl": true, "policy_refused": false,
 "policy": {"managed": false, "minlen": 12, "minclass": 3, "maxrepeat": 3, "dictcheck": 1,
            "usercheck": 1, "difok": 5, "remember": 5, "max_days": 99999, "min_days": 0,
            "warn_days": 7, "deny": 0, "unlock_time": 900, "fail_interval": 900,
            "existing": false},
 "nodes": [{"name": "isemon1", "me": true, "alive": true, "at": 1794775600.0, "pending": 0,
            "error": "", "admin_group": "wheel", "shells": ["/bin/bash", "/usr/sbin/nologin"],
            "uid_min": 1000, "uid_max": 60000, "today": 20772,
            "users": [{"name": "jnovak", "uid": 1000, "gecos": "Jan Novák", "home": "/home/jnovak",
                       "shell": "/bin/bash", "login": true, "groups": ["jnovak", "wheel"],
                       "sudo": true, "password": true, "locked": false, "must_change": false,
                       "changed": 20752, "expires": null, "max_days": 90, "min_days": 1,
                       "warn_days": 7, "pw_ends": 20842, "home_there": true, "root": false}],
            "before": [], "said": [{"at": 1794775500.1, "id": "a1b2c3d4e5f6", "do": "add",
                                    "name": "jnovak", "by": "boss", "ok": true,
                                    "said": "jnovak made"}],
            "policy": {"pwquality": {}, "remember": 0, "faillock": {}, "aging": {}, "pam": {},
                       "authselect": null, "managed": false, "pwscore": false},
            "policy_applied": true, "policy_said": "the system's own", "policy_error": ""}]}
```

Days (`changed`, `expires`, `pw_ends`, `today`) are days since 1970-01-01, as
in `/etc/shadow`.

`POST /api/osusers` (`nodes` may be given and is not needed):

| `action` | other fields | answer |
|---|---|---|
| `refresh` | | `{"message": "asked again", "nodes": ["NODE"]}` |
| `add` | `name`, `gecos`, `shell`, `password` (`""` = none), `must_change`, `sudo` | `{"message": "done on NODE within a few seconds", "nodes": ["NODE"]}` |
| `set` | `name`, `gecos`, `shell` | as above |
| `password` | `name`, `password`, `must_change` | as above |
| `aging` | `name`, `max_days`, `min_days`, `warn_days` | as above |
| `sudo` | `name`, `on` | as above |
| `lock` / `unlock` | `name` | as above |
| `drop` | `name`, `home` | as above |
| `policy` | `policy` (the object above, each value range-checked) | `{"message": "each node puts it in within a few seconds", "policy": {…}}` |

The answer means the change was **asked**; what root did shows in the next
GET (`said`, `pending`, `error`). Refusals come back as 400 with the words.

## Command line and console

```
isemon --local-users                                  # the users of this machine
isemon --local-user add jnovak --local-full-name "Jan Novák" --local-must-change   # the password is asked
isemon --local-user password jnovak                   # asked at the terminal, twice
isemon --local-user sudo-on jnovak                    # sudo-off
isemon --local-user lock jnovak                       # unlock
isemon --local-user aging jnovak --local-max-days 90 --local-min-days 1 --local-warn-days 7
isemon --local-user drop jnovak                       # asks first (--yes); drop-home: with the home folder
isemon --local-policy                                 # as set, and as in effect here
isemon --local-policy-set managed=1 minlen=14 minclass=3 max_days=90 deny=5 existing=1
isemon --local-policy-set managed=0                   # as the system has it
```

A password is asked at a terminal only - never given on the command line.
The command line goes through the daemon's API as the page does, with the
same checks. In `isemon --console`: *Network, time and power → Local users*.
