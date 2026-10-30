# Updates of the operating system

*Settings → System updates* (isemon 1.10.239, after otp 1.0.158-1.0.160, for
one server). What dnf (or apt) has waiting on this server, and an update of
all of it from the page, with a bar and what the package manager says as it
goes. Nothing here runs until somebody asks for it: until a look or an update
is asked for, root is asked nothing and nothing is kept.

## What the pane shows

- **The server's card** - how many updates are waiting, how many of them are
  security updates, whether a restart will be needed, when it was last looked
  at and by what (`dnf` or `apt`). *what is waiting* folds the packages out.
  *Look for updates* looks again (`dnf --refresh check-update`, or
  `apt-get update` and `apt list --upgradable`).
- **A restart, told before the update** - a look also says whether the update
  will need a restart once it is in: the packages it is for (kernel, glibc,
  systemd, linux-firmware, dbus, microcode, zlib, libc6, linux-image...) are
  named on the card and above *Update it now*. It also says whether a restart
  is waiting already (`dnf needs-restarting -r`, or Debian's
  `/var/run/reboot-required`); then *This server needs a restart* is offered
  at once, with *Restart this server*.
- **Update this server** - *After the update*: *Ask me when a restart is
  needed* or *Restart by itself when needed*. *Update it now* updates every
  package (`dnf -y --refresh upgrade`, or `apt-get -y upgrade` keeping the
  configuration files as they are).
- **The update** - who started it and when, a bar, the step it is in (waits to
  begin, updating, restarting, done, failed), what happened. *Hide this* once
  it is over.
- **What it says** - the package manager's last lines as they come. *Hide it*
  / *Show it* is for this browser only; *Clear the window* empties it for every
  page and after a reload too - what comes after is shown.

Anybody signed in may look; only a full administrator may look for updates,
update, restart or clear the window.

## When it begins, and stopping it

An update waits about ten seconds before it begins; until then **Stop it**
cancels it and nothing is updated. Once the package manager is at work it is
not stopped half way: it finishes.

An update is refused while:

- an upgrade of isemon from the pages is running,
- a restart or a power-off is under way,
- a change of the network is under way or on trial (keep it or put the old one
  back first),
- a look for updates is going on.

While the package manager is at work, a restart, a power-off, an upgrade of
isemon and a change of the network are refused in turn.

## After the update

What is waiting is looked at again by itself. When the update needs a restart:

- with *Ask me when a restart is needed* the pane offers *Restart this server*
  (the same restart as *Settings → Restart and power off*);
- with *Restart by itself when needed* the server is restarted at once, and
  the update is done when it is up again.

After a restart the server is looked at again, so a restart that was waiting
is not shown as waiting any more.

The logs go on being read while the packages are updated. An update may
restart the services whose packages it updates (nginx, PHP-FPM, the database
server) - for a moment the page or the database may not answer.

## How it is done

The daemon runs as `isemon` and may not install anything. It asks root the
same way as for the network and the clock:

1. It lays `/var/lib/isemon/web/osup.ask` down - `{"do": "run", "kind":
   "check" | "upgrade", "id": ..., "at": ...}`.
2. `isemon-web.path` (which watches `osup.ask` from 1.10.239 on) starts
   `isemon-web.service`, and `/usr/local/lib/isemon/isemon_web.py` checks the
   ask as root: only `run` with `check` or `upgrade`, an id, and made within
   the last five minutes - an ask left behind is never done later by
   surprise. It answers in `osup.ans` at once.
3. The work itself runs outside root's own service, as a unit of its own
   (`systemd-run ... isemon_web.py --os-job ID check|upgrade`), so a long
   update holds no other ask up. It holds `/run/isemon-osup.lock` (opened
   without following a link) while it runs: one look or update at a time.
4. The work writes how far it is, its phase and its last lines into
   `osup.json` about once a second. A page asking reads them from there; the
   database keeps only what was asked and how it ended (meta keys
   `osup:check`, `osup:checkwant`, `osup:plan`, `osup:row`, `osup:seen`,
   `osup:cleared`).

Every start, end, failure and restart of an update is written into Events.

Before 1.10.239 the path unit did not watch `osup.ask`: until
`./install.sh --upgrade` has been run once the pane says root's half does not
do updates yet, and nothing is asked. `install.sh --upgrade` only puts the new
helper and path unit in; it updates no package of the system.

## By hand

    systemctl status isemon-web.path
    journalctl -u 'isemon-os-*'              # the work's own units
    cat /var/lib/isemon/web/osup.json        # how far it is, its last lines
