# Upgrades: on the command line, or from the page

Two ways to put in a new version (isemon 1.10.222 and later). Both stay: use
whichever suits you.

| | Command line | The page |
|---|---|---|
| Where | on the machine, as root | *Settings → Monitoring and updates → Upgrades*, as a full administrator |
| How | `./install.sh --upgrade` | send the `.tar.gz`, press *Upgrade* |
| What it checks | nothing - root trusts what it runs | the package is signed by a release key this machine trusts |
| How far it is | install.sh's own words | a bar, the step install.sh is at, and its words |

Either way the database, the settings and the accounts are kept, isemon
restarts once for a few seconds, and the logs are read on from where they
were.

## On the command line

```
tar xzf isemon-X.Y.Z.tar.gz && cd isemon-X.Y.Z
sudo ./install.sh --upgrade
```

## From the page

1. **Send the package** - `isemon-X.Y.Z.tar.gz` as released. It is checked at
   once (below) and waits; *What changed* shows its entry from the README.
2. **Upgrade.** The package and a request are laid down in
   `/var/lib/isemon/upgrade/`; systemd (`isemon-upgrade.path`) starts
   `isemon-upgrade.service`, which runs `/usr/local/lib/isemon/isemon_upgrade.py`
   **as root**. It is the only thing that unit can do.
3. **The bar**: checking the package, then each step of `install.sh
   --upgrade --yes` as it says it (`@@progress N/8 …`, said only when it was
   started from the page), then *isemon is restarting - asking again…*
   while the daemon answering the page is the one restarting, and 100 % once
   it answers again. The page offers to load itself again in the new version.
4. If it fails, the bar turns red and says why; *What install.sh said* is
   the whole of it (`/var/lib/isemon/upgrade/last.log`). The program that was
   there stays, or is put back by install.sh itself.

`isemon --web-status` and `isemon --upgrade-status` show the same on the
command line.

### From the web (1.10.228)

*Settings → Upgrades → From the web* looks once a day (and when *Look now* is
pressed) at `upgrade_url` for `isemon-X.Y.Z.tar.gz` packages:

| `upgrade_url` | how it is read |
|---|---|
| `https://github.com/OWNER/REPO/tree/BRANCH/FOLDER` (the default: `https://github.com/falco81/ISEMon/tree/main/release`) | GitHub's API lists the folder; the packages come from `raw.githubusercontent.com`. When the API refuses (sixty questions an hour without an account), the folder's own page is read for the names. |
| a web page or a folder listing (nginx, Apache autoindex) | every link to an `isemon-X.Y.Z.tar.gz` |
| one package's address | that package |

HTTPS only, and never followed on to anything that is not HTTPS. A proxy, if
the server needs one, comes from `https_proxy` in the service's environment
(`systemctl edit isemon`: `Environment=https_proxy=…`). The server needs to
reach the address (and `api.github.com`, `raw.githubusercontent.com` for
GitHub); isemon's own firewall chain only ever filters what comes in.

The newest one newer than what runs here is offered: **Upgrade to X now**
fetches it, has it checked exactly as a package sent by hand (below - the
signature of a release key this server trusts, every file in it) and begins
the upgrade; **Only fetch it** stops before the upgrade and leaves it waiting.
When more than one version newer than this one is there (1.10.231), a list
above the buttons picks which - the newest unless another is chosen; with
only one, there is no list. Nothing is ever put in by itself. `upgrade_check`
off stops the daily look;
*Look now* still asks. A new version found is said once in Events.

On the command line:

```bash
isemon --upgrade-check              # what is at upgrade_url, and whether it is newer
isemon --upgrade-online             # the newest: fetched, checked, put in, followed
isemon --upgrade-online 1.10.230 --yes
isemon --upgrade-follow             # follow one going on, with its progress bar
isemon --upgrade-status             # the last one, what waits, what the web has
```

Ctrl+C in `--upgrade-follow` stops the following, not the upgrade.

### Going back to an older version (1.10.232)

Off as it comes (1.10.233): *Offer going back to an older version*
(`downgrade_offered`, Settings → Upgrades) shows the card and lets it be done;
off, the card is not there and going back is refused on the page, by `isemon
--downgrade` and in the console alike. Every older version on the card has
*What changed* - its entry out of this version's own README, which keeps every
version's; `isemon --downgrade-check --changes` prints them, and the console
offers it before it goes back.

*Settings → Upgrades → Going back to an older version*, `isemon
--downgrade-check` / `isemon --downgrade VERSION`, and the console's
*Upgrades → Go back to an older version*: back to a version published at
`upgrade_url`, **only as far back as can still run on the database as it is**.

Nothing is copied or put back - on a database of a terabyte that is the only
way going back can be done at all. The older version opens the database as it
is; the settings of later versions wait in it (they are not deleted) and are
there again after the next upgrade.

How far back is safe is `DOWNGRADE_FLOOR` in `isemon.py`: the oldest version
that can still run on a database this one has used - the same tables, the same
columns added later, the same indexes, the same split tables. It is 1.10.226 in
1.10.232: the database has had exactly that shape from 1.10.226 on. It is
raised whenever a version changes that shape (test/fixes232.py holds the shape
and fails when it changes, so it is never forgotten), and every version writes
its floor into the database it runs on, where it only ever rises - so a version
gone back to still knows how far back the newest one that ran here allowed.

It is checked three times:

- **the page and the command line** list every older version at the address as
  *safe* or *not safe* (and why), and refuse while anything is half done - an
  upgrade, a change of the network or of the firewall waiting to be kept, a
  restart, a backup or another long job over the database;
- **the daemon** refuses below the floor - its own or the database's, whichever
  is higher;
- **root** (`isemon_upgrade.py`) refuses below the floor written in root's own
  copy of the installed program, and below the one the daemon passed: the isemon
  account can raise it, never lower it. Root also keeps the highest floor any
  installed version has named, in `/usr/local/lib/isemon/downgrade-floor`
  (1.10.234), so going back twice - each step above the floor of the version
  installed then - never gets below what the database has seen. The package
  is checked exactly as an upgrade is - signed by a release key this server
  trusts.

Going back to a version without the console (before 1.10.228) takes the
console's login script (`/etc/profile.d/zz-isemon-console.sh`) away once its
`install.sh` went through, so root's login is not told the option is unknown. The page asks for the version to be
typed before it goes; `isemon --downgrade VERSION` asks the same unless
`--yes`.

Below the floor, going back is done by hand: the older package's `install.sh
--upgrade`, with a dump or copy of the database from before the version that
changed its shape put back - see *The database*.

### What makes it safe

The service runs as `isemon`, which may not write a byte of the program. The
page therefore never installs anything itself:

- Root copies the package to a folder of its own before reading it, so it
  cannot be changed under the check, and checks it again from the start:
  - **signed**: `MANIFEST` lists the SHA-256 of every file and
    `MANIFEST.sig` is its Ed25519 signature, by one of the keys in
    `/usr/local/lib/isemon/release-keys/` - root's alone, put there only by
    `install.sh`;
  - every file is the one signed, and nothing else is in it: no link, no
    device, no path outside its one folder, not bigger than 64 MB;
  - it is not older than what is installed (going back is done on the
    command line).
- Then it runs the package's own `install.sh --upgrade --yes`, exactly as
  somebody would by hand, and stops it if it has not finished in 20 minutes.

A package that was changed, or signed by a key this machine does not know,
is refused - put it in on the command line if you trust it.

## The release key

Each package carries the public half of the key it was signed with
(`deploy/release-keys/*.pub`); `install.sh` puts it into
`/usr/local/lib/isemon/release-keys/` and takes out the keys the package does
not carry. The private half is never in a package and never on a server.

**When the key changes** (a new key for a new run of releases), the page
refuses the first package signed with it - *the signature is not by any
release key this machine trusts*. Put that one version in on the command
line once (`./install.sh --upgrade`): that installs its key, and from then on
the page takes the packages signed with it again.

The first version with this (1.10.222) has to be put in on the command line
once as well: that installs the units, the helper and the key.

## Signing a release

```
tools/release.py isemon-X.Y.Z /path/to/private.key isemon-X.Y.Z.tar.gz
```

writes `MANIFEST` and `MANIFEST.sig` into the folder, checks the signature
against `deploy/release-keys/`, and packs it.
