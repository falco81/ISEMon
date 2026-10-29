# The isemon console

`isemon --console` - the whole of isemon by its menus, on the server's own
screen or over SSH. With `isemon --console-at-login on` (what install.sh sets
on a fresh install) it opens by itself when **root** signs in; **q** leaves it
for the ordinary shell, exactly as it was before, and `isemon --console` opens
it again.

It is a port of otp's console (otp 1.0.130 - 1.0.136): the same look, the same
keys, the same windows. It opens on the **live log** (every line); Esc goes to
the main menu.

```
 isemon 1.10.228  ise-mon1   service active        1,234 banned | logs read | 3 account(s)

  Main menu

     1  Status and checks
     2  Live log
     3  Failed attempts, logins and who is kept out
     4  Banning and the whitelist
     5  The firewall and the router
     6  Accounts of the dashboard
     7  Settings
     8  The database and backups
     9  Network, time and power
    10  Upgrades
    11  The service

 Up/Down move   Enter choose   Esc back   ! shell   q leave
```

- **The bar at the top**: the version, the machine, whether the service runs
  (`systemctl is-active isemon`), how many addresses are banned, whether the
  logs are being read (`logs read`, or `logs NOT read for 12 min`) and how many
  accounts the dashboard has. Too narrow a window drops the last of them, or
  puts them on the line below. On the lines under it, as `isemon --status
  --json` says them: banning switched off, a database that will not open, the
  one verdict the dashboard's header draws when it is not "ok" (no ISE log,
  the firewall out of sync...), a setting that could not be read, a long job
  going on, a change of the network or the firewall waiting to be kept (where
  this version has one), and - in red - a daemon that is not answering. Asked
  again every 30 s without holding anything up, and not at all while a live
  view, a page or a shell is open.
- **The menus** are a text screen: arrows (or j/k) move, Enter or Right
  chooses, Esc, Left or Backspace goes back, a number jumps to its item (`1`
  `1` is 11), Home/End and PgUp/PgDn, `!` a shell, `q` leaves. Only what
  changed is written, so nothing blinks; made bigger or smaller (PuTTY too),
  the screen is drawn again to its size.
- **Nothing is typed at a bare prompt.** Every question is a window over the
  menu: its fields one under the other - Up/Down (Tab) move between them, a
  choice (a role, how long a ban lasts, on / off) is changed with
  Left/Right, a password shows only stars, the field's help is under them -
  and Enter checks them all before anything is run (a needed one left
  empty, a number out of its limits, an address that is none, two passwords
  not the same, a file that is not there: it says which, and the window
  stays). Esc closes it. Anything that cannot be undone (delete, let
  everybody in, take ours off the router, put a copy back, erase, a restart,
  an upgrade, switching the machine off) asks Yes / No first - No unless
  chosen.
- **Lists**: who is kept out, the whitelist, the accounts and the backups
  kept here are lists to scroll - arrows, PgUp/PgDn, Home/End, a scroll bar
  on the right, `/` to keep only the rows with some words - and Enter on one
  offers what can be done with it:
  - a ban: everything about the address, let it back in;
  - a whitelisted address: take it off (one from the `never_block` setting
    is changed in Settings);
  - an account: set its password, change its role, switch it off / on, show
    it, delete it;
  - a backup: put it back.
- **Every action is the `isemon ...` command its window shows in its
  title**, run as it would be typed - the console can do nothing the command
  line cannot. A short answer comes in a window; a long one on a screen of its
  own to scroll (arrows, PgUp/PgDn, Home/End, a scroll bar; Esc, q or Enter
  back).
- **Options another version has.** The menus offer the network, the time,
  power, remote backups and upgrades from the web whether or not this version
  has them. The command line's own parser is asked first: an option it does
  not know is said as "not in this version" in a window, never run.
- **Passwords never go on a command line**, where `ps` shows them: a new
  account and a new password go to `isemon --add-user` / `--passwd` through
  `ISEMON_PASSWORD`; a secret setting to `isemon --set KEY=@env` through
  `ISEMON_VALUE_KEY` (the command line takes that too). Making the database
  on a server asks for its administrator's password on the terminal itself.
- **Settings > Browse and change**: every setting in its group, with its value
  (set ones bright, defaults dim) and key; Enter opens a window with its help,
  what it is now and as it comes, and what it may be - a switch or a list
  chosen with the arrows, a number between its limits, a text typed (a secret
  as stars) - checked exactly as the daemon checks it before `isemon --set`
  saves it; a wrong value says why and the window stays. **Change one by its
  key** opens the same window for a key typed. The firewalls whose log is read
  (`fwlog_sources`) are a list of their own and are changed on the dashboard.

## What the menus run

| Menu | Commands |
| --- | --- |
| 1 Status and checks | `--status`, `--status --files`, `--check`, `--jobs`, `--stop-job`, `--events`, `--web-status` |
| 2 Live log | the live view of the daemon's log |
| 3 Failed attempts, logins | `--failed`, `--passed --kind`, `--blocked`, `--address`, `--ptr` (with `--limit`, `--hours`, `--search`) |
| 4 Banning | `--ban` (`--minutes` / `--forever`, `--why`), `--unban`, `--unban all`, `--whitelist`, `--allow`, `--unallow`, `--ban-sources`, `--unban-source`, `--fold`, `--mikrotik --purge`, `--rescan` |
| 5 The firewall and the router | `--mikrotik`, `--mikrotik --sync`, `--fw-test`, `--fw-key --fw`, `--geo-sync`, `--mikrotik --purge`, `--banfeed`, `--ios-acl`, `--fetch` |
| 6 Accounts | `--users`, `--add-user --role [--must-change]`, `--passwd`, `--set-role --role`, `--disable-user`, `--enable-user`, `--del-user` |
| 7 Settings | `--settings`, `--set KEY=VALUE` (`KEY=@env` for a secret), `--export` |
| 8 The database and backups | `--database`, `--database test`, `--database setup`, `--backup`, `--backup --full`, `--dump`, `--restore FILE --yes`, `--erase WHAT --yes`, `--rbackup-status`, `--rbackup-now` |
| 9 Network, time and power | `--change-keep net\|fw`, `--change-back net\|fw`, `--net`, `--time`, `--time-step`, `--reboot --yes`, `--poweroff --yes` |
| 10 Upgrades | `--upgrade-check`, `--upgrade-online VERSION --yes`, `--upgrade-follow`, `install.sh --upgrade` from a package file, `--web-status` |
| 11 The service | `systemctl status / restart isemon`, `systemctl status nginx php-fpm`, `journalctl -u isemon -f`, the console at login |

## The live views

The live log (`/var/log/isemon/isemon.log`) and the journal (`journalctl -u
isemon -f`) are screens of their own:

- The newest line at the bottom, followed as it comes (`following`).
  Up/PgUp/Home scroll back - the view then stays where it is (`PAUSED, 12 new
  below`) - and Down/PgDn to the end, End or Enter follow again. Left/Right
  move sideways along long lines. A scroll bar on the right says where you
  are; the last 20 000 lines are kept. A log rotated under it is followed into
  the new file.
- **Whatever is typed is a grep**, as `grep -i`: the lines with it, in any
  case, stay; the hits are marked. A regular expression works
  (`banned|let back`, `mikrotik.*answer`); text that is not one is taken as it
  is. Backspace takes a character back, Ctrl+U all of them; Esc clears it,
  and Esc again goes back to the menu.
- Coloured (colorama): the time dim, the level by how bad, what it is about
  in cyan, addresses in magenta, banned / refused / failed in red, let back
  in / signed in / synced in green, a warning line yellow and an error line
  red. Only colour is added: every column stays where it was in the file.
- Colour with colorama when it is installed (install.sh installs it); without
  a colour terminal, with `NO_COLOR` or with `--no-color`, plain text.
- `ISEMON_CONSOLE_START=menu isemon --console` opens on the menu instead.

## Terminals

- Lines and boxes are drawn as UTF-8 characters where the terminal is UTF-8
  (`NCURSES_NO_UTF8_ACS`, as PuTTY shows them), and as `+ - |` where it is
  not; a character the terminal cannot show is a `?`, never an error.
- A window too small for a box gets a smaller one, never an error; no colour
  is fine.
- Ctrl+C leaves the console with the terminal as it was.

## At login

`/etc/profile.d/zz-isemon-console.sh` (from `deploy/isemon-console-login.sh`)
opens it for root in an interactive login shell only - never for a command run
over SSH (`ssh mon1 uptime`), scp or sftp, a script, a shell opened from the
console itself (`!`), or when `ISEMON_NO_CONSOLE=1` is set (`ssh -t mon1
ISEMON_NO_CONSOLE=1 bash -l`).

```bash
isemon --console-at-login off      # root lands in the shell; isemon --console still works
isemon --console-at-login on
isemon --console-at-login status
```

On the pages (1.10.230): *Settings - About - The console*, a switch for the
same thing, put in by root's helper (isemon_web.py) - a full administrator
switches it, anybody signed in sees how it stands.

The choice is `/etc/isemon-console-login` (`on` / `off`), in /etc itself where
only root writes - not in /etc/isemon, whose group the daemon's account is in.
It is written beside it and renamed into place, and read only when it is a
plain file: a link put there is replaced, never followed, and a pipe is never
waited on. No file is off.

install.sh switches it on for a **fresh** install only. An upgrade puts the
profile script in and never makes or changes the choice, so a plain upgrade
changes nothing about root's login: `isemon --console-at-login on` switches
it on there. `install.sh --uninstall` takes the profile script and the choice
away.
