# Certificates from acme (acme push)

acme - the certificate manager of ours - gives the dashboard its certificate
and renews it by itself, as it does for otp and zigmon. This is isemon's half
of protocol 1; the whole protocol, as both sides speak it, is
[acme-push-protocol.md](acme-push-protocol.md).

**One more way in, nothing else changes** (chapter 0 of the protocol). It is
off until it is switched on; upload by hand, a request (CSR), a self-signed
one, the TLS settings, Automatic certificates, download/export, backups and
the command line work exactly as before, with it off and with it on - and any
of them simply replaces a pushed certificate. A push goes through the very
code an upload does (`WebRoot.tls_do`, action `upload`); nothing of it was
changed for this.

## Setting it up

1. **Settings → Certificates and TLS → Certificates from acme**: switch on
   *Take certificates from acme* and **Save the changes** (the card's
   switches, a pasted key and *Forget it* wait for the save bar, as every
   setting does). isemon makes its id and its sealing key
   (X25519) once; the private half is sealed in the database.
2. *Pair with an acme*: a code is shown **once** (16 letters,
   `XXXX-XXXX-XXXX-XXXX`, 15 minutes, five wrong tries and it is gone).
3. In acme: Targets → *An application of ours (acme push)*: the address the
   card shows (`https://NAME/` - the dashboard), the code in *Pairing code*,
   *Try*. Then *Discover* and *Make the certificates*.

acme's address has to be among those that may reach the dashboard
(**Firewall and access**). Instead of a code, acme's own key
(`acme-push-ed25519 AAAA… acme@acme1`) may be pasted (*Or paste acme's key*).

## What isemon offers

One slot: `node:<host>` - the dashboard of this machine, its names
`acme_name` (Automatic certificates' name; unsaid, the name of the
certificate it has, else the machine's full host name). It takes an ECDSA or
an RSA certificate, or both (`alt`): RSA as the certificate and ECDSA beside
it, as Automatic certificates keep a dual one.

`inventory` says what is there now and who looks after it: `own-acme`
(Automatic certificates), `acme-push`, `manual` (uploaded, a request,
self-signed) or `none`. A machine without root's helper for the web server
says `installable: false`.

## What a push does

Each request is signed by a paired acme (Ed25519, ±300 s, every nonce once -
kept in the database); the certificate's key travels sealed to this
installation. isemon checks the fingerprint, opens the key, that it is the
certificate's, that the certificate is valid now and holds the dashboard's
name (unless *Take certificates of other names* is on and acme asks for it),
and then hands it to **the upload's own code**, which keeps it exactly where an
upload keeps it (meta `web_tls`, the key sealed) and writes its event; `how`
is then `acme push: <acme>`, and a twin goes beside it as Automatic
certificates puts one; root puts it into nginx within
seconds. Automatic certificates leave it alone from then on (*Look after it*
there gives it back). The same certificate again is `already` and touches
nothing. Every pairing, wrong code, pasted or forgotten key and every push is
an event; nothing of a body or a key is ever logged.

*Forget it* beside a paired acme, or switching it off, ends it: the
certificate the dashboard has stays as it is.

## The pages

`index.php` answers `?api=acme-push-hello` (GET), `-pair`, `-inventory`,
`-install` (POST) before any session or same-page check - nothing a browser
can be made to send carries a valid signature - and hands the body, byte for
byte, with the five `X-Acme-Push-*` headers to the daemon
(`/api/acme-push/OP`). The primitives are the `cryptography` module's where
it is installed, plain Python (and openssl for AES) where it is not.
