# SSH keys of root

Since 1.10.351 this page is **[SSH keys](ssh-keys.md)**: root's keys are only
shown there, and the keys of every other user who may sign in are made, added
and taken away there.

Root's keys - the lines of `/root/.ssh/authorized_keys` - are no longer made,
added or taken away from isemon: not on the page, not with `--root-key-add`,
`--root-key-drop` or `--root-key-make`, not through `/api/sshkeys` (403).
Change them on the server itself, as root. With a key in root's file the
`isemon` account would be root outright; root's helper has no code left that
writes it. `isemon --root-keys` still lists them, and what sshd makes of root.

The keys made for root here before stay where they are, as lines of root's
file like any other.
