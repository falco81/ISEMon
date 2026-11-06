# Alerts on every page (1.10.312)

What wants doing is said on every page, to a full admin, as a band under the
header - except what is about upgrading, which is under Settings → Upgrades
(1.10.313), with a number on the Settings tab and on Upgrades - - one for each thing, worst first (red: trouble, amber: worth a look).
Each says what was found, why it matters and the steps, with every command
ready to copy; *Open it* goes to the pane that says more; *Not now* puts it
away on that browser for a day, or until what it says changes. Nobody else is
sent them. `isemon --status` says them too.

They ride on the status the page asks for every few seconds (`alerts`:
`[{key, level, title, says, steps: [{say, text}], pane}]`); a new kind of
alert is one more function whose answer `alerts_now` adds.

## The parts root installs, older than the program

`install.sh` puts some files in as root, as they are in the package:

| | installed as |
|---|---|
| `deploy/isemon_web.py` | `/usr/local/lib/isemon/isemon_web.py` - root's helper (the firewall and TLS from the pages, the network, the clock, root's keys, logrotate) |
| `deploy/isemon_upgrade.py` | `/usr/local/lib/isemon/isemon_upgrade.py` |
| `deploy/isemon_main.py` | `/usr/local/lib/isemon/isemon_main.py` |
| `deploy/isemon-web.service`, `isemon-web.path` | `/etc/systemd/system/` - what hands the pages' requests to root |
| `deploy/isemon-upgrade.service`, `isemon-upgrade.path` | `/etc/systemd/system/` |
| `deploy/isemon.service` | `/etc/systemd/system/isemon.service` |
| `deploy/isemon.logrotate` | `/etc/logrotate.d/isemon` |

An upgrade from the web runs `./install.sh --upgrade` by itself. A package
copied over by hand, or an `install.sh` that stopped half way, leaves the
program new and these old: what is new in them - a request the page may now
make of root, say - then does nothing, and nothing said why.

So the daemon compares each of them, every ten minutes, with the sha256 this
version ships (`ROOT_PARTS` in `isemon.py`). One that is different or missing
is a band - trouble where it is root's helper or its units, worth a look for
the rest - with the command:

```bash
./install.sh --upgrade
```

as root, in the folder the package was unpacked in. The band goes by itself
within ten minutes once they match. On a machine isemon is not installed on
as a service (no `/etc/systemd/system/isemon.service`) nothing is said.

`ROOT_PARTS` is made by `python3 tools/root_parts.py`; `test/fixes312_alerts.py`
fails while it does not match `deploy/`, so a change to one of those files
cannot be released without it.

### Done lately, and Clear (1.10.318)

Below the bands, *Done lately* lists what went: **done** (somebody pressed
Done, named under Who) or **gone by itself** (the check found it right). The
last 30 are kept in `meta` (`todo_done`). **Clear**, at the right of its
heading, empties the rows the pane shows - `POST /api/todo {"do": "clear",
"items": [[title, at], ...]}`; without `items`, all of it - and is written to
Events as `"done lately" cleared by <who> (<how many>)`. It never touches what
is still to be done, nor a row that came while the pane was open. The list,
and Clear with it, is drawn only when it has rows.

## Trouble on the disks and in the logs

What Settings → Disk and logs counts as trouble - a disk 95 % full or full
within three days at the rate measured, logs no logrotate file takes, a log
two files take - looked at behind every half hour, never in the way of the
status. *Open it* opens the pane, which has the steps (and, for logrotate,
the button that has root put it right).
