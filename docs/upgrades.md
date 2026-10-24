# Upgrades: on the command line, or from the page

Two ways to put in a new version (isemon 1.10.222 and later). Both stay: use
whichever suits you.

| | Command line | The page |
|---|---|---|
| Where | on the machine, as root | *Settings → This server → Upgrades*, as a full administrator |
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

`isemon --web-status` shows the same on the command line.

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
