# SSH keys of root

*Settings → SSH keys of root* shows the keys that may sign in to this server
as root over SSH - the lines of `/root/.ssh/authorized_keys` - and lets a full
administrator make a new key, add one of their own, export one or take one
away. (After otp's page of the same name, 1.0.158-1.0.161, without its cluster
parts: isemon is one server, so there is no node to choose and nothing to put
"on again where it is missing".)

Nothing is changed until somebody asks for it on the page. Opening the pane
only reads the file; the keys are not read at all until the pane is opened.

## What the page shows

- **A key for root** - drawn as the key of a router is. *Make a key* makes a
  fresh pair here: **Ed25519** (the strongest, and short) or **RSA 4096**
  (where something old needs RSA). Its public half goes into root's
  `authorized_keys`; its **private half is shown once**, to download or copy,
  and kept nowhere - not in the database, not in a log, not in an event, not
  in a file on the server. Close the window without keeping it and it is gone;
  take the key away in the list and make another. A key put there before
  stays until it is taken away in the list.
- **Keys that may sign in as root** - one row a key: its kind (ED25519,
  ECDSA, RSA with its bits), its SHA256 fingerprint and its comment. A key made
  here is marked *made here*; a line with options before the key (`from=…`,
  `command=…`) is marked *with options*. Beside each key:
  - *Export* saves its public half as a `.pub` file named by its comment;
  - *Take it away* removes its line, after you confirm it. When it is the
    last key root signs in with, it is asked again, and only then taken away.
- *Add a key* takes a key you have already: one line of a `.pub` file
  (`ssh-ed25519 AAAA… you@laptop`), typed, pasted or read from the file - or
  the **private key** itself, with its passphrase if it has one: its public
  half is worked out here (`ssh-keygen -y`) and only that is used. The private
  half and the passphrase are not kept.
- **This server's card** - how many keys there are, what sshd makes of root
  (`PermitRootLogin`), whether it takes passwords (`PasswordAuthentication`),
  the SSH port, the file and when it was read. When sshd does not let root
  sign in at all (`PermitRootLogin no`), or takes no keys
  (`PubkeyAuthentication no`), the pane says so above the list: the keys are
  not used until it does.

## What is taken

- Ed25519, ECDSA (256, 384, 521), the FIDO kinds (`sk-ssh-ed25519@openssh.com`,
  `sk-ecdsa-sha2-nistp256@openssh.com`) and RSA of **3072 bits and more**.
- Refused: RSA under 3072 bits, DSA, a line with options before the key, more
  than one line, anything ssh-keygen does not read.
- A key that is there already is no fault: it is not written twice.

## How it is written

The daemon runs as `isemon` and may not touch root's files. What the page asks
is laid down in `/var/lib/isemon/web/sshkeys.ask`; `isemon-web.path` starts
root's helper (`isemon_web.py`, `isemon-web.service`), which checks every
value again, does it and answers in `sshkeys.json`:

- only `/root/.ssh/authorized_keys` is written, and only whole: a new file,
  **0600 root:root**, made beside it and renamed over it;
- the folder `/root/.ssh` is made **0700** when it is not there; when it is a
  link, or the file is a link, nothing is read or written through it;
- every line it does not understand - comments, keys with options, anything
  else - is kept as it was;
- the last key root signs in with is taken away only when said again;
- an add or a take-away asked more than ten minutes before root's helper
  comes to it is not done (one left lying, for example, while the helper was
  not installed yet).

Every change - a key added, taken away, made, or one root refused - is
written into **Events**, with who asked for it.

Only a full administrator sees the pane and may use it; a read-only account
does not see it and is refused by the daemon.

## Installing

`./install.sh --upgrade` puts in the new helper and the line
`PathExists=/var/lib/isemon/web/sshkeys.ask` of `isemon-web.path`; nothing else
on the machine changes. Until it is run, the pane says root's half is not
installed and neither reads nor changes anything.

Making or reading a key needs `ssh-keygen` (`dnf install openssh-clients`); the
facts of sshd need `sshd -T`.
