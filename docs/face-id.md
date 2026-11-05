# Face ID as the second step of signing in (1.10.303)

Face ID, Touch ID, Windows Hello or the PIN of a device - a *passkey*
(WebAuthn) - as the second step of every sign-in. It is not a way in of its
own: the name and the password come first, as before.

## Switching it on

Settings → Accounts → *Face ID as the second step of signing in
(passkeys)*. Off as it comes. It is switched on from the page only when that
page is opened by its name over https (`https://isemon.example.cz/`), with a
certificate the browser trusts: WebAuthn works nowhere else, and switched on
from a page opened by an address nobody could sign in again.

```bash
isemon --set passkeys=1        # on (0: off - nothing is taken away)
```

Those signed in already stay signed in; the next sign-in of each asks.
Switched off again, a sign-in still waiting for Face ID ends rather than
becoming a whole one.

## Signing in

1. The name and the password, as always.
2. **The first time** (onboarding): *Set up Face ID*. The device asks for
   Face ID (Touch ID, Windows Hello, its PIN) and keeps a passkey; an iPad or
   an iPhone keeps it in the iCloud Keychain, so it is on the person's other
   Apple devices too. The sign-in is then whole.
3. **Every time after that**: *Use Face ID*, and the sign-in is whole.

Until then the page is the sign-in page still, with that step on it, and the
daemon answers nothing for that sign-in but the step itself and signing out.
Five refusals end it.

A passkey is bound to the name the page was opened by: one made on
`isemon.example.cz` does nothing on `10.0.0.5` or on another name.

## Your account

*Face ID*: every passkey of the account - which device, for which name, when
it was added and last used. Another device is added there - by a sign-in
that is whole, and within ten minutes of Face ID (*Confirm it is you, to add
another* first), so that a sign-in left open on somebody's screen cannot add
one of its own. One is taken away there; the last one taken away, the next
sign-in sets Face ID up again.

Out of the directory a person may sign in as `jnovak` or as
`jnovak@corp.example`: their passkeys are theirs under either name.

## Setting it up again for somebody

A lost iPad, a new phone: Settings → Accounts → the account → **Face ID** →
*Set it up again*. Every passkey of theirs is taken away and their next
sign-in sets Face ID up again; every sign-in of theirs ends (a lost iPad is
signed in too). A full admin only; it is written down in Events. From the
server, with nobody signed in:

```bash
isemon --passkey-reset NAME     # or: all
```

## What is checked

On every answer of the browser: the type of question, a question this server
asked - once, within five minutes, of this person, on this sign-in - the page
it came from (`https://` + the name), that the passkey is for this name,
that somebody was there **and that the device checked it was them** (user
verification: without it, it is no second step), the signature (ES256, RS256
or Ed25519, by openssl) and the counter (one that goes back may be a copy).
The server keeps only the public half of each passkey, in `meta`; at most 20
an account.
