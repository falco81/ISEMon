# test/otp-tls

What `test/fixes245_otptls.py` opens: `isemon-tls.zip` in the shape otp's
*Settings → isemon → Encrypted sending → Make the file for isemon…* makes it
(1.0.172) - `ca.pem`, `isemon.crt`, `isemon.key`, `10-otp-tls.conf` and
`README.txt`, every entry WinZip AES-256 and deflated - written by pyzipper,
an implementation that is not isemon's own, so the reading is checked against
somebody else's writing. `aes128-stored.zip` is one entry, AES-128, stored.

The passphrase of both is `correct-horse-battery`. The authority, the
certificate and the key in them are made for these tests alone (CN
isemon.example.net, 192.0.2.10) and are trusted by nothing.
