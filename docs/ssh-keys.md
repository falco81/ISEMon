# SSH keys

*Settings → SSH keys* (full administrators only): the keys that may sign in to
this server over SSH - as root, or as any other user who may sign in here. It
follows acme's page of the same name (1.0.108, 1.0.240), for one server: there
is one node, this machine, and nothing to choose between nodes.

Nothing is changed until somebody asks for it. Opening the pane only reads;
the keys are not read at all until the pane is opened.

## root (1.10.239; only shown since 1.10.351)

The lines of `/root/.ssh/authorized_keys`: each key's kind (ED25519, ECDSA,
RSA with its bits), its SHA256 fingerprint and its comment, *with options*
where the line has some before the key. Each can be exported by its public
half (a `.pub` file). Above the list the pane says what sshd makes of root:
`PermitRootLogin no`, root not among `AllowUsers`, or no keys taken at all
(`PubkeyAuthentication no`) - the keys are not used until sshd lets them be.

### Root's keys are only shown

Since 1.10.351 root's keys are **not made, added or taken away** from isemon -
not on the page, not on the command line, not through the API. Change them
**on the server itself, as root**: `/root/.ssh/authorized_keys` (an editor,
`ssh-copy-id root@server` from your machine, or `ssh-keygen` there). isemon
reads the file again when the pane is opened, and with the refresh button.

With a key in root's `authorized_keys`, the `isemon` account - a fault in the
daemon, anybody who can drop a file into its folder - would be root outright.
So the rule is held in every layer, not only on the page:

| Layer | What it does with a change of root's keys |
|---|---|
| the page | no *Make a key*, *Add a key* or *Take away* for root |
| `POST /api/sshkeys` | **403** *root's SSH keys are only shown on the pages - change them on the server itself, in /root/.ssh/authorized_keys* for `add`, `drop` and `uk_make`, and the old `rk_make`, `rk_given`, `rk_again`. A body without `user` is root's |
| the daemon | `sshkeys_ask` refuses anything but a read for root - no ask is written; one found in its queue anyway is refused, never handed to root |
| root's helper | `sshkeys_do` refuses anything but `list` for root, from whatever asks it - a file laid in `/var/lib/isemon/web` by itself included. It reads root's file (never through a link, a plain file only, 1 MB at most) and has **no code left that writes it** |
| the command line | `--root-key-add`, `--root-key-drop`, `--root-key-make` are refused with the same words; `--root-keys` still lists |

The keys made for root on the pages before 1.10.351 stay where they are: they
are lines of root's file now, like any other.

## Every other user who may sign in (1.10.351)

*Whose keys* picks root or a user of this machine who may sign in: a UID from
`UID_MIN` to `UID_MAX` of `/etc/login.defs` (1000 to 60000), a login shell
(not `nologin`, `false`, `sync`, `shutdown` or `halt`) and a home folder of
their own. Local users of `/etc/passwd`; directory users of sssd appear when
the machine lists them. The accounts of the services are never among them -
`isemon` itself, nginx and php-fpm's, the database's, chrony, sshd and the
others - whatever their UID.

For such a user:

- **Make a key** makes a fresh pair here: **Ed25519** (the strongest, and
  short) or **RSA 4096** (where something old needs RSA). Its **private half
  is shown once**, to download or copy, and kept nowhere - not in the
  database, a log, an event or a file on the server. Its public half goes
  into the user's `~/.ssh/authorized_keys`. A key there before stays until it
  is taken away in the list.
- **Add a key** takes a key you have already: one line of a `.pub` file
  (`ssh-ed25519 AAAA… you@laptop`), or the **private key** itself with its
  passphrase if it has one - its public half is worked out here
  (`ssh-keygen -y`, the passphrase handed over through its askpass from the
  environment, never on a command line) and only that is used. The private half and the passphrase
  are not kept.
- **Export** and **Take away** in the list. There is no "last key" guard for
  a user: their password stays.

### What is taken

- Ed25519, ECDSA (256, 384, 521), the FIDO kinds (`sk-ssh-ed25519@openssh.com`,
  `sk-ecdsa-sha2-nistp256@openssh.com`) and RSA of **3072 bits and more**.
- Refused: RSA under 3072 bits, DSA, a line with options before the key, more
  than one line, anything ssh-keygen does not read.
- A key that is there already is no fault: it is not written twice.
- At most 300 lines of a file are read by ssh-keygen, and 1 MB of it at all:
  a huge file in a user's home cannot stall root's helper.

### Written as the user, never through a link

The daemon runs as `isemon` and may not touch anybody's files. What the page
asks is laid down in `/var/lib/isemon/web/sshkeys.ask`; `isemon-web.path`
starts root's helper (`isemon_web.py`), which checks every value again and
answers in `sshkeys.json`. A user's file is read and written **by a child of
the helper that is that user** - their UID, GID and groups:

- the home folder must be a real folder of the user's own (not a link);
- `~/.ssh` is made **0700** when it is not there, and refused when it is a
  link or not a folder;
- `authorized_keys` is refused when it is a link (to `/etc/shadow`, to
  `/root/.ssh`…) - never followed; a new file, **0600**, is written beside it
  and renamed in;
- then, as root, `restorecon` runs on those two paths only, never `-R`.

So nothing a user puts in their own home can make root write anywhere else.
An add or a take-away asked more than ten minutes before the helper comes to
it is not done.

## The API

`GET /api/sshkeys` answers as acme's pane reads it, with `"cluster": false`
and one node, this server - and, as before, root's `keys`, `sshd`, `file`,
`at`, `error`, `pending` at the top:

```json
{"ok": true, "keygen": true, "cluster": false, "helper": true,
 "nodes": [{"name": "isemon1", "me": true, "alive": true, "at": 1794775600.2, "pending": 0,
            "error": "", "file": "/root/.ssh/authorized_keys",
            "keys": [{"fp": "SHA256:…", "type": "ED25519", "bits": 256, "comment": "admin@laptop",
                      "options": false, "readable": true, "text": "ssh-ed25519 AAAA… admin@laptop"}],
            "sshd": {"there": true, "permit_root": "prohibit-password", "allow_users": "",
                     "pubkey": "yes", "password": "no", "port": "22"},
            "users": [{"name": "jnovak", "uid": 1000, "home": "/home/jnovak", "shell": "/bin/bash"}],
            "keys_of": {"jnovak": {"at": 1794775605.0, "error": "",
                                   "file": "/home/jnovak/.ssh/authorized_keys", "keys": []}},
            "before": []}],
 "kept": []}
```

`POST /api/sshkeys` (`nodes` may be given and is not needed):

| Body | Answer |
|---|---|
| `{"action": "refresh", "user": "jnovak"}` (`user` left out: root) | `{"message": "asked again"}` |
| `{"action": "add", "user": "jnovak", "line": "ssh-ed25519 AAAA… c", "passphrase": ""}` | `{"message": "the key goes onto NODE within a few seconds"}` |
| `{"action": "drop", "user": "jnovak", "fp": "SHA256:…"}` | `{"message": "the key is taken away on NODE within a few seconds"}` |
| `{"action": "uk_make", "user": "jnovak", "kind": "ed25519"\|"rsa4096", "scope": "all"\|"NODE"}` | `{"private": "-----BEGIN OPENSSH PRIVATE KEY-----…", "pub": "…", "fp": "SHA256:…", "nodes": ["NODE"], "file": "isemon-jnovak-YYYYMMDD", "message": "made - keep the private half now, it is not shown again"}` |
| any change with `user` root or left out | **403** |
| a bad value | 400 `{"error": "…"}` |

Every change - a key added, taken away, made, or one root refused - is written
into **Events**, with who asked for it and for which user; never a private key.

## On the command line

    isemon --root-keys                   # root's keys, read afresh, and what sshd says
    isemon --root-keys --json

`--root-key-add`, `--root-key-drop` and `--root-key-make` are refused since
1.10.351. The keys of the other users are changed on the page.
