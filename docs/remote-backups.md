# Backups to another machine

*Settings → Backups* (isemon 1.10.228 and later) sends a backup of everything
to another machine - on a schedule, or now - and puts one back. One backup
brings the whole installation back onto a machine installed from nothing.

It is the same system as otp's *Settings → Backups*, with the same page: the
destinations, the schedule, the history and putting one back all work the same
way. Nothing happens until somebody sets it up: there is no destination and
the schedule is off after an install and after an upgrade.

## What is in a backup

One file, `isemon-backup-SITE-HOST-YYYYMMDD-HHMMSS.tar.gz.enc` (SITE is the
installation's name, *Settings → About*, HOST this machine's short name):

| File inside | What |
|---|---|
| `about.json` | what it is, where and when it was made - read first, so a backup can be looked at without unpacking the rest |
| `RESTORE.md` | the exact steps to put this backup back, filled in with what it is |
| `isemon-full.db` | the **full backup** - the same file as `isemon --backup --full` or *Download a full backup*: the whole database as a file any of the three engines takes (every record, the bans, the accounts, every setting saved on the pages, the certificate of the pages, the firewall and who may reach which page), with the keys in it: `settings.key` (opens every password kept in the database), `banfeed.key`, `known_hosts`, and this machine's `config.json` to read (its secrets left out) |
| `manifest.json` | the same as `about.json`, and the SHA-256 of every file above - last, because the copy's checksum is known only once it has gone through |

Beside it, **not** locked, go `...tar.gz.enc.sha256` (to check the file) and
`...-RESTORE.md` (the same steps, readable before anything is opened). Neither
holds a secret.

A large database takes a while: a PostgreSQL of tens of gigabytes is copied
first (*Settings → The database* shows the copy being made), then packed and
locked as one stream into the file - nothing of it is ever held in memory, and
nothing is ever written to the disk unlocked except the copy itself, which is
taken away as soon as it is packed. Before anything is begun, the room on the
disk is checked: the copy and the packed file beside it need about one and a
half times the size of the database in `/var/lib/isemon/backups`. Not enough
room is said, in numbers, and nothing is made.

### Everything, or the configuration only

*What is backed up* (`rbackup_what`) chooses what every backup holds - the
ones sent to the destinations, and the one made to download:

- **Everything, the logs too** (`all`, as it comes and as it always was): the
  full backup above. Put back, it replaces the whole database.
- **The configuration only, without the logs** (`config`): no copy of the
  database at all, so it is small and quick however big the logs are. Its
  name ends in `-config` (`isemon-backup-SITE-HOST-YYYYMMDD-HHMMSS-config.tar.gz.enc`),
  and the lists on the page mark it *configuration only*. Inside, instead of
  `isemon-full.db`, is `isemon-config.json`: what a complete export
  (`isemon --export FILE --secrets`) carries - every setting saved on the
  pages with its passwords, the accounts with theirs, the whitelist, who is
  banned now, the routers' keys and the directory's certificate - and the
  pages' own settings (their certificate, the firewall and who may reach
  which page), the destinations of the backups, the names of the VLANs and
  the routers' API keys, with `settings.key`, `banfeed.key` and `known_hosts`.
  No record of any log, no counts, nothing fetched (GeoIP, public lists - they
  are fetched again), and never where a log was read up to.

It is locked and checked exactly as a full backup is, and kept on its own:
*Backups kept at each destination* and *And none older than* count the full
backups and the backups of the configuration each apart, so a backup of the
configuration made every day never takes the last full one away (1.10.238).

## Locked with a password

*The password of the backups* (on the same page) locks every backup:
`openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -md sha256`. It is opened by
isemon (`isemon --restore-bundle`, or *Put one back…* on the page), or with
openssl alone on any machine:

```bash
openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -md sha256 \
    -in isemon-backup-....tar.gz.enc -out isemon-backup-....tar.gz
```

The password is kept in the database, sealed with `settings.key` like every
other password there - so it is inside every backup too, which helps nobody who
does not have it. **Keep it in a password vault, apart from the backups.**
*Make a strong one* makes a random one and shows it once.

**Without a password nothing is sent**: an unlocked backup would hand the key
that opens every password kept here - the routers', the directory's, the
database's - to whoever can read the destination. A scheduled or a by-hand run
stops with "the backups have no password", and *Download one here* is refused
too.

## Where they go

*Add a destination* - as many as you like (up to 20); every one switched on
gets every backup.

| Kind | What it needs | Signing in | Checked |
|---|---|---|---|
| A folder | a path on this machine (an NFS, CIFS or other mount); the `isemon` account must write there, and isemon.service must be let write there (below) | - | - |
| FTP | server, port 21, folder | account and password - **unencrypted on the way** (the file itself is locked) | - |
| FTPS | server, port 21 (explicit, AUTH TLS) or 990 (implicit), folder | account and password; a client certificate if the server wants one | the server's certificate: against the system's authorities, an authority of your own, a pinned fingerprint, or (not safe) not at all |
| SFTP | server, port 22, folder | an SSH key made here or your own (with its passphrase), an SSH certificate if the server wants one, or a password | the server's host key, trusted once |
| SCP | as SFTP; needs a shell on the server (`ls`, `mv`, `rm` through ssh) | as SFTP | as SFTP |
| SMB | server, port 445, share, folder in it | account, password, domain | SMB2 at least; SMB3 encryption required (on by default) |

SFTP and SCP use OpenSSH's own `sftp`, `scp` and `ssh` (`openssh-clients`), SMB
`smbclient` (`samba-client`). `install.sh` puts both in whenever they are
missing - on an install and on every upgrade (1.10.236). The page says when one
is missing still (no repository reachable): `dnf install openssh-clients` or
`dnf install samba-client`.

A file is written under a temporary name and renamed when it is whole, so a
half-sent backup is never taken for one. Every password, key and passphrase of
a destination is kept in the database sealed, is never shown back on the page
(a password as its last two letters), and is never written into the log or
Events. A password reaches ssh through `SSH_ASKPASS` and smbclient through an
authentication file of its own - never a command line, where `ps` would show
it.

What is typed is checked before it is kept: a folder or a share with `;` or
`"` in it, a folder beginning with `-`, and an account beginning with `-` are
refused (smbclient takes `;` as the next command, ssh a leading `-` as an
option).

### A folder outside /var/lib/isemon

isemon.service runs with `ProtectSystem=strict`: it may write only in
`/var/lib/isemon`, `/var/log/isemon` and `/etc/isemon`. For a mount anywhere
else, let it write there once - an upgrade leaves this as it is:

```bash
systemctl edit isemon
#   [Service]
#   ReadWritePaths=/mnt/backup/isemon
systemctl restart isemon
chown isemon /mnt/backup/isemon          # or give the isemon group write
```

Without it *Try it* says "outside the folders isemon.service may write in".

### SSH keys

*Make a key* makes an ed25519 pair here; the private half is kept in the
database, sealed, and never leaves the machine unless you *Download it*
(written into Events). The public half is shown with the line to run on the
server:

```bash
mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo 'ssh-ed25519 AAAA… isemon-backup@isemon1' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys
```

*Use my own* takes a private key you have (OpenSSH or PEM, with its passphrase
if it has one). Restricting the key on the server is a good idea, e.g. an
SFTP-only account in a chroot.

### The server's host key

The first *Try reaching it* shows the server's fingerprint. Compare it with the
server's own (`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on it) and
*Trust it*. From then on a server answering with another key is refused - if it
was reinstalled on purpose, *Forget it* and trust the new one.

### FTPS certificates

- **Against an authority of my own**: paste the certificate of the authority
  that signed the server's.
- **Pinned**: exactly this certificate - *Try reaching it* shows the server's
  SHA-256 fingerprint and *Pin this certificate* takes it. A renewed server
  certificate has to be pinned again.
- **Client certificate**: *Make one* (EC P-256, five years) and give the
  server's administrator the certificate shown (*Download it*), or *Use my own*
  - PEM (certificate and key) or a PFX/PKCS#12 file with its password.
- The data connection resumes the TLS session of the control connection, as
  vsftpd, ProFTPD and FileZilla Server require.

## When, and how many

| Setting | |
|---|---|
| *Backups to the destinations on a schedule* (`rbackup`) | on: a backup is made and sent at the time below. Off by default |
| *At* (`rbackup_at`) | `HH:MM`, this machine's clock (04:15) |
| *How often* (`rbackup_every`) | daily, or weekly on *On (1 Monday - 7 Sunday)* (`rbackup_day`) |
| *Backups kept at each destination* (`rbackup_keep`) | this machine's newest N stay at each destination (30); older ones are taken away after each backup (with their .sha256 and RESTORE.md). The newest and the one just sent are never taken away, and only backups this installation sent itself are: another machine's - even one whose name looks the same - never |
| *And none older than (days)* (`rbackup_keep_days`) | older ones go too; 0: only the count |
| *The password of the backups* (`rbackup_password`) | a secret setting, kept sealed |

They are ordinary settings: `isemon --settings` shows them (the password as
its last two letters) and `isemon --set` changes them. The password is best set
on the page, where it never passes through a shell's history.

*Back up now* sends one at once; *Download one here* makes one and saves it on
the computer you are sitting at (the download starts when it is ready - a
large one takes minutes; it waits here for an hour at most). *What was sent*
lists every backup with where it went, how long it took and what each
destination said; Events has it too. *Clear the list* empties it, and the bin
on a line takes that line off. Only the list changes: the backups stay at the
destinations (*Backups there* deletes them).

On the command line:

```bash
isemon --rbackup-status            # the destinations and the last backups
isemon --rbackup-now               # one now, to every destination switched on
```

## Putting one back

**On the page**: *Backups there* on a destination lists its backups -
*Download*, *Put this back…*, *Delete*. Or *Put one back…* at the top sends a file
from your computer (sent as the file itself, at most 4 GB as nginx takes it;
a larger one is put back on the command line). Before anything is replaced a
copy of the database as it is is made (*Settings → The database*), as every
restore makes one. Then the database is replaced, the keys the backup carries
are put in place (the ones there before kept beside them as
`*.before-restore-*`), and the daemon reads its settings again. The sessions
are the backup's too: you sign in again afterwards, with an account the backup
has.

**On a machine installed from nothing** (the server is lost):

```bash
tar xzf isemon-VERSION.tar.gz && cd isemon-VERSION && ./install.sh
systemctl stop isemon
isemon --restore-bundle isemon-backup-....tar.gz.enc         # what is in it
isemon --restore-bundle isemon-backup-....tar.gz.enc --yes   # put it back
systemctl start isemon
```

The password is asked for, or comes from `--passphrase-file FILE` (its first
line) or `ISEMON_BACKUP_PASSWORD`. The database and its keys come back; the new
machine keeps its own `/etc/isemon/config.json` - which database it opens, its
port - so the backup goes into whichever engine the new machine is set to use.
The old machine's config.json is in the backup to read (in the
`isemon_carried` table of `isemon-full.db`).

**A backup of the configuration only** is put back the same three ways, and
replaces nothing. The machine's own `settings.key` stays its own (1.10.238):
what the backup's key sealed - the passwords of the destinations, the pages'
private key - is opened with it and sealed again with this machine's; only a
machine with no key at all takes the backup's. `banfeed.key` and `known_hosts`
are put in place (the ones there before kept beside them). A configuration
this machine refuses (two settings that may not go together) changes nothing.
Then the configuration is put back as `isemon --import` puts one back -
the settings, the accounts, the whitelist and the bans written into the
database the machine has - and the pages' own settings after it. Every log
record the machine has stays exactly as it is, and no copy of the database is
made first, because nothing in it is replaced. What it could not bring is said
(as an import says it).

Every backup's own `RESTORE.md` has these steps with its own names and version
in them. *How to put it back* at the top of *Settings → Backups* shows the same
file as a backup made now would carry it, and *Download RESTORE.md* saves it -
keep it with the password, apart from the backups.

## Troubleshooting

| What it says | What to do |
|---|---|
| *the backups have no password* | set *The password of the backups* (*Make a strong one*), save |
| *... is outside the folders isemon.service may write in* | a folder destination: `systemctl edit isemon`, `ReadWritePaths=` (above) |
| *the isemon account may not write into ...* | a folder destination: `chown isemon /mnt/backup/isemon` (or give the isemon group write) |
| *making a backup needs about ... free in ...* | make room in `/var/lib/isemon/backups` (old copies, *Settings → The database*) |
| *the server's certificate is not trusted* | FTPS: the server's certificate is not from an authority this machine trusts - give its authority, or pin it |
| *the server shows another host key than the one trusted* | SFTP/SCP: reinstalled on purpose? *Forget it*, *Try reaching it*, compare, trust. Otherwise somebody is in between |
| *the server did not let the account in* | the public key is not in `authorized_keys` yet, or the password is wrong |
| *the server did not take the account and password (NT_STATUS_LOGON_FAILURE)* | SMB: account, password or domain |
| *... is not on this machine* | `dnf install openssh-clients` or `dnf install samba-client` |
| *the password does not open it* | the backup was locked with another password than the one set now: type that one when putting it back |
