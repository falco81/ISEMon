# eduroam answered by a Windows NPS

The eduroam module reads FreeRADIUS by default (radius.log and its detail
files; see eduroam.cz's FreeRADIUS 3 guide). A site whose eduroam RADIUS is a
**Windows NPS** can set **Settings → The eduroam logs → Which server writes
the eduroam logs** to `nps`. isemon then reads NPS's own log and builds the
same eduroam page from it: the same cards, lists and popups.

The NPS setup itself is eduroam.cz's own guide:
<https://www.eduroam.cz/cs/spravce/pripojovani/radius/nps>. What matters for
isemon is below.

---

## What NPS has to log

*Accounting → Change Log File Properties* on the NPS server, as for the NPS
module ([nps-logs.md](nps-logs.md), step 1):

| Setting | Value |
|---|---|
| Settings tab | **Accounting requests**, **Authentication requests** |
| Log File tab → Format | **ODBC (Legacy)** |
| Create a new log file | monthly or daily |

Getting the files to the isemon machine works the same as for the NPS module:
NXLog with [`nxlog-nps.conf`](nxlog-nps.conf) and
[`deploy/nps/06-nps-store.conf`](../deploy/nps/06-nps-store.conf), or a share
mounted read-only ([nps-logs.md](nps-logs.md), §2).

---

## Settings → The eduroam logs

| Setting | Value |
|---|---|
| Read the eduroam logs | on |
| Which server writes the eduroam logs | `nps` |
| Where the eduroam server writes | the folder(s) holding NPS's `IN*.log`, one per NPS |
| Which files in each are NPS's | `IN*.log` (the default) |
| Which of NPS's answers are eduroam's | empty for an NPS that serves only eduroam; otherwise e.g. `eduroam*` |
| Accounts to leave out altogether | e.g. the monitoring account eduroam.cz tests your server with |

**Which answers are eduroam's.** eduroam.cz's guide builds eduroam out of
*connection request policies*: one for your own realm, which NPS
authenticates against the directory, and one for everybody else, which NPS
forwards to the national servers (flr1–3.eduroam.cz). If the same NPS also
answers the switches or a VPN, name the eduroam policies here, for example
`eduroam*`. The pattern is matched against the connection request policy,
the network policy and the wireless network (the SSID, where the access
points append it to Called-Station-Id). Everything else in those files is
left to the NPS module.

The same files can be read by both modules at once: the eduroam module takes
eduroam's answers and the NPS module takes all of them. Both then show the
eduroam sign-ins, each under its own door.

---

## What comes out of it

| On the eduroam page | From NPS |
|---|---|
| Account | the name NPS resolved in the directory (`DOMAIN\jan`) with the institution from the outer identity: `jan@example.cz`. A visitor keeps their outer identity, `anonymous@cvut.cz`. |
| Institution | what follows the @ in the outer identity |
| One of ours or a visitor | who checked it: *Windows* for your own realm, *the national eduroam servers (passed on)* for a visitor, with the national server it went to |
| Why a refusal was refused | NPS's reason code, in words |
| The machine | its MAC (Calling-Station-Id) |
| Where it was, the address it was given | NPS's accounting lines in the same file. The newest per machine is kept and put beside that machine's sign-ins, as FreeRADIUS's detail files are. This needs the access points or controller to send accounting to NPS. |

The switches' own "is the server there" probes are left out, as in the NPS
module. Put the account eduroam.cz's monitoring tests with into *Accounts to
leave out altogether*, as with FreeRADIUS.

**Nothing here is ever judged.** The only address on these records is the
controller or the national server the request came through.

To read every month still in the folders again from the beginning:

```bash
isemon --rescan --logs eduroam
```
