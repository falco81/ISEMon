# Before Windows Server 2025 (1.10.321)

**Domain → Before Windows Server 2025** lists what a domain controller of
Windows Server 2025 refuses that a 2016 one still lets through, and which
machines and accounts here still do it.

It is off unless switched on, under **Settings → The domain controllers →
Look for what Windows Server 2025 will refuse** (`winsec_ad2025`). While it is
off, nothing is counted and the page is not there.

## What it finds, and in which log

| Kind | How bad | Log | Events | What breaks on 2025 | Fix |
|---|---|---|---|---|---|
| LDAP simple bind in the clear | refused | Directory Service | 2889 (binding type 1) | simple bind on 389 without TLS: `strongerAuthRequired`, result 8 | LDAPS on 636 or StartTLS; the controller by FQDN; trust the root CA |
| LDAP bind without signing | refused | Directory Service | 2889 (binding type 0) | SASL (NTLM/Kerberos) bind on 389 without signing | signing/sealing in the library, or LDAPS |
| LDAP channel binding failed | refused | Directory Service | 3039 | NTLM/Kerberos over LDAPS without a channel binding token, once required | a library that sends the token, or a simple bind over LDAPS |
| NTLMv1 | refused | Security | 4624 `Package Name (NTLM only): NTLM V1` | NTLMv1 is gone | LmCompatibilityLevel 5, or a newer device |
| Kerberos with DES | refused | Security | 4768/4769, ticket type 0x1/0x3 | DES is not there | take DES off the account |
| Kerberos with RC4 | from July 2026 | Security, System (KDC) | 4768/4769 type 0x17/0x18; a client offering no AES; KDC 201–209 | no RC4 for accounts that do not ask for it (KB5073381) | `msDS-SupportedEncryptionTypes` 24, password reset, AES keytabs |
| An account with no AES keys | from July 2026 | Security, System (KDC) | 4768/4769 `Available Keys` without AES; KDC 14/16/26/27 | its tickets fail without RC4 | reset its password |
| SMB1 to a controller | refused | SMBServer/Audit | 3000 | SMB1 is not on 2025 | SMB 2/3 |
| A password handed over as it is | info | Security | 4624 logon type 8 | in the clear it is refused (2889 says which) | LDAPS |
| NTLM | info | Security, NTLM/Operational | 4776, 8004 | still works (NTLMv2), on its way out; Protected Users cannot use it | Kerberos: names, SPNs |
| The controller's daily count | info | Directory Service | 2887, 3040, 3041 | — | the detailed logging names the clients |

### 3. Whether everything on a controller is as it should be

The KDC part of the System log, SMBServer/Audit and NTLM/Operational are
written to only when something happens: a missing key or RC4, a connection
over SMB1, or NTLM with its audit policy on. If nothing has arrived from one of
them, it may simply have had nothing to say, so the page shows it in grey
rather than red.

Run this script as administrator on each controller, either pasted whole into
a PowerShell window or saved as a `.ps1`. It changes nothing and checks:

- the audit policy;
- the LDAP logging;
- the SMB1 and NTLM audit;
- the sizes of the logs;
- what each log wrote in the last seven days;
- NXLog: its service, its configuration and its errors.

Replace `ISEMON_HOST` with isemon's address (the page fills it in itself).
Every line says OK, WARN or FAIL. If a log has events but the page still says
nothing came from it, NXLog is not sending that log.

```powershell
# isemon - Before Windows Server 2025: is this domain controller set up to tell it all?
# Run as administrator on each controller. Changes nothing; every line says OK, WARN or FAIL.
# Pasted whole into a PowerShell window, or saved as a .ps1 and run.
& {
    $n = @{ok = 0; bad = 0}
    function Say($state, $what, $more) {
        $colour = @{OK='Green'; WARN='Yellow'; FAIL='Red'; INFO='Gray'}[$state]
        Write-Host ('{0,-5} {1}' -f $state, $what) -ForegroundColor $colour -NoNewline
        if ($more) { Write-Host "  - $more" -ForegroundColor DarkGray } else { Write-Host '' }
        if ($state -eq 'OK') { $n.ok++ } elseif ($state -ne 'INFO') { $n.bad++ }
    }

    Write-Host "`n== Audit policy (Security log) ==" -ForegroundColor Cyan
    $want = [ordered]@{
        'Credential Validation'              = 'Success and Failure'
        'Kerberos Authentication Service'    = 'Success and Failure'
        'Kerberos Service Ticket Operations' = 'Success and Failure'
        'Logon'                              = 'Success and Failure'
        'Account Lockout'                    = 'Failure'
    }
    foreach ($sub in $want.Keys) {
        $line = (auditpol /get /subcategory:"$sub" /r | ConvertFrom-Csv | Select-Object -First 1)
        $has = $line.'Inclusion Setting'
        $need = $want[$sub]
        $good = ($has -eq 'Success and Failure') -or ($need -eq 'Failure' -and $has -match 'Failure')
        if ($good) { Say OK "$sub" $has } else { Say FAIL "$sub" "is '$has', wants '$need'" }
    }
    $force = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue).SCENoApplyLegacyAuditPolicy
    if ($force -eq 1) { Say OK 'Advanced audit policy overrides the basic one' } else { Say WARN 'Advanced audit policy may be overridden by the basic one' 'GPO: Audit: Force audit policy subcategory settings = Enabled' }

    Write-Host "`n== LDAP (Directory Service log) ==" -ForegroundColor Cyan
    $ldap = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' -ErrorAction SilentlyContinue).'16 LDAP Interface Events'
    if ($ldap -ge 2) { Say OK '16 LDAP Interface Events' "= $ldap (2889 names who binds in the clear or unsigned)" } else { Say FAIL '16 LDAP Interface Events' "= $ldap, wants 2" }
    $sign = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -ErrorAction SilentlyContinue).LDAPServerIntegrity
    $cbt  = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -ErrorAction SilentlyContinue).LdapEnforceChannelBinding
    Say INFO 'LDAP signing required (LDAPServerIntegrity)' "$(if ($sign -eq 2) {'2 - required'} elseif ($null -eq $sign) {'not set - not required'} else {"$sign - not required"})"
    Say INFO 'LDAP channel binding (LdapEnforceChannelBinding)' "$(if ($null -eq $cbt) {'not set - never'} else {$cbt}) (0 never, 1 when supported, 2 always)"

    Write-Host "`n== SMB1 and NTLM audit ==" -ForegroundColor Cyan
    $smb = Get-SmbServerConfiguration
    if ($smb.AuditSmb1Access) { Say OK 'SMB1 access audited (SMBServer/Audit 3000)' } else { Say FAIL 'SMB1 access not audited' 'Set-SmbServerConfiguration -AuditSmb1Access $true -Force' }
    if ($smb.EnableSMB1Protocol) { Say WARN 'SMB1 server is ON on this controller' 'Windows Server 2025 has none: what uses it shows on the SMB1 tile' } else { Say OK 'SMB1 server is off' }
    $ntlm = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -ErrorAction SilentlyContinue).AuditNTLMInDomain
    if ($ntlm -eq 7) { Say OK 'Audit NTLM authentication in this domain' 'Enable all (NTLM/Operational 8004)' } else { Say FAIL 'Audit NTLM authentication in this domain' "is '$ntlm', wants 7 (GPO: Network security: Restrict NTLM: Audit NTLM authentication in this domain = Enable all)" }
    $inc = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -ErrorAction SilentlyContinue).AuditReceivingNTLMTraffic
    if ($inc -eq 2) { Say OK 'Audit Incoming NTLM Traffic' 'for all accounts' } else { Say WARN 'Audit Incoming NTLM Traffic' "is '$inc', wants 2 (optional)" }
    $block = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -ErrorAction SilentlyContinue).RestrictNTLMInDomain
    if ($block -and $block -ne 0) { Say WARN 'NTLM is RESTRICTED in this domain (RestrictNTLMInDomain)' "= $block - that blocks, not audits" }

    Write-Host "`n== Log sizes ==" -ForegroundColor Cyan
    foreach ($l in @(@('Security', 1024), @('Directory Service', 256), @('System', 20),
                     @('Microsoft-Windows-SMBServer/Audit', 8), @('Microsoft-Windows-NTLM/Operational', 64))) {
        $log = Get-WinEvent -ListLog $l[0] -ErrorAction SilentlyContinue
        if (-not $log) { Say FAIL $l[0] 'this log is not on this controller'; continue }
        $mb = [int]($log.MaximumSizeInBytes / 1MB)
        if (-not $log.IsEnabled) { Say FAIL $l[0] 'switched off' } elseif ($mb -ge $l[1]) { Say OK $l[0] "$mb MB" } else { Say WARN $l[0] "$mb MB, wants $($l[1]) MB or more: wevtutil sl `"$($l[0])`" /ms:$($l[1] * 1MB)" }
    }

    Write-Host "`n== What each log wrote in the last 7 days ==" -ForegroundColor Cyan
    $since = (Get-Date).AddDays(-7)
    foreach ($q in @(
        @{N='Security 4768 (TGT)';           Log='Security'; Id=4768; Need=$true}
        @{N='Security 4769 (service ticket)'; Log='Security'; Id=4769; Need=$true}
        @{N='Security 4776 (NTLM)';          Log='Security'; Id=4776; Need=$true}
        @{N='Directory Service 2887 (daily)'; Log='Directory Service'; Id=2887; Need=$false}
        @{N='Directory Service 2889 (who)';  Log='Directory Service'; Id=2889; Need=$false}
        @{N='Directory Service 3039-3041';   Log='Directory Service'; Id=3039,3040,3041; Need=$false}
        @{N='System KDC 14/16/26/27';        Log='System'; P='Microsoft-Windows-Kerberos-Key-Distribution-Center'; Id=14,16,26,27; Need=$false}
        @{N='System KDC 201-209 (RC4)';      Log='System'; P='Microsoft-Windows-Kerberos-Key-Distribution-Center'; Id=201,202,203,204,205,206,207,208,209; Need=$false}
        @{N='SMBServer/Audit 3000 (SMB1)';   Log='Microsoft-Windows-SMBServer/Audit'; Id=3000; Need=$false}
        @{N='NTLM/Operational 8004';         Log='Microsoft-Windows-NTLM/Operational'; Id=8004; Need=$false})) {
        # The KDC's own events only: other programs write 14 and 16 into the System log too.
        $f = @{LogName=$q.Log; Id=$q.Id; StartTime=$since}
        if ($q.P) { $f.ProviderName = $q.P }
        $got = (Get-WinEvent -FilterHashtable $f -ErrorAction SilentlyContinue | Measure-Object).Count
        if ($got -gt 0) { Say OK $q.N "$got" } elseif ($q.Need) { Say FAIL $q.N '0 - the audit above that writes it is off' } else { Say INFO $q.N '0 - nothing happened, or its switch above is off' }
    }
    $e = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769} -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($e) {
        if ($e.Message -match 'Available Keys') { Say OK '4769 names the keys an account has' 'accounts with no AES keys can be seen' } else { Say WARN '4769 does not name the keys an account has' 'the January 2025 updates (or later) add it' }
    }

    Write-Host "`n== NXLog ==" -ForegroundColor Cyan
    $svc = Get-Service nxlog -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') { Say OK 'nxlog service running' } else { Say FAIL 'nxlog service' "$(if ($svc) {$svc.Status} else {'not installed'})" }
    $conf = 'C:\Program Files\nxlog\conf\nxlog.conf'
    if (Test-Path $conf) {
        $text = Get-Content $conf -Raw
        foreach ($i in 'eventlog_security','eventlog_ds','eventlog_kdc','eventlog_smb1','eventlog_ntlm') {
            $in = $text -match "(?m)^\s*<Input $i>"
            $routed = $text -match "(?m)^\s*Path\s+.*\b$i\b"
            if ($in -and $routed) { Say OK "nxlog.conf: $i" 'an input, and in the Route' } elseif ($in) { Say FAIL "nxlog.conf: $i" 'an input, but not in the Route Path' } else { Say FAIL "nxlog.conf: $i" 'missing' }
        }
        $host_ = ([regex]::Match($text, '(?m)^\s*define\s+SYSLOGHOST\s+(\S+)')).Groups[1].Value
        if ($host_ -and $host_ -ieq $env:COMPUTERNAME) { Say OK 'SYSLOGHOST' "$host_ - this controller's name" } else { Say WARN 'SYSLOGHOST' "'$host_' but this controller is $env:COMPUTERNAME - its logs land in that folder" }
    } else { Say FAIL 'nxlog.conf' "not at $conf" }
    $nlog = 'C:\Program Files\nxlog\data\nxlog.log'
    if (Test-Path $nlog) {
        $errs = Select-String -Path $nlog -Pattern 'ERROR' | Select-Object -Last 5
        if ($errs) { Say WARN 'nxlog.log has errors' 'the last ones:'; $errs | ForEach-Object { Write-Host "      $($_.Line)" -ForegroundColor DarkYellow } } else { Say OK 'nxlog.log has no errors' }
    }
    $dest = 'ISEMON_HOST'
    $tcp = Test-NetConnection $dest -Port 514 -WarningAction SilentlyContinue
    Say INFO "TCP 514 to isemon ($dest)" "$(if ($tcp.TcpTestSucceeded) {'open - the TCP output would work'} else {'closed - stay on UDP, or open it'})"

    Write-Host ("`n{0} OK, {1} to look at" -f $n.ok, $n.bad) -ForegroundColor $(if ($n.bad) {'Yellow'} else {'Green'})
}
```

## On the Domain overview

With this page switched on, *Domain → Overview → Worth looking at* also says
what these logs found, each as one line. The front page's Domain card shows
the same lines. The kinds are:

- **A password sent to LDAP in the clear** (warn);
- **Sign-ins with NTLMv1** (warn);
- **Kerberos tickets in DES** (warn);
- **SMB1 to a domain controller** (warn);
- **LDAP binds without signing** (info);
- **LDAP channel binding failed** (info);
- **Accounts with no AES keys** (info).

Each line says:

- how many there were, from how many machines and accounts;
- which machine and account did the most;
- what fixes it.

Pressed, it opens this page at that kind, by machine or by account.

RC4 and NTLM are not repeated there. The overview already has its own line
for RC4 tickets, and NTLM as a whole is ordinary.

The lines appear only while this page is switched on and its logs have
found something in the overview's window. Without them, the overview is
exactly what it was before.

## How it is counted

The rules are matched when each line is read, and only for the event numbers
above. Only a few words of each line are read, never the whole of it.
Matching happens before any event the site has switched off (sign-ins,
directory reads) is dropped, so it works either way.

Each finding is counted in `ad25_seen`: one row per day, kind of trouble,
client, account and controller, holding how many times it was seen and when
it was first and last seen. Rows are kept for 90 days (NTLM for 31).

A line read again is not counted again. This covers a rotated file, the pass
back over every log, and the same line arriving in two files. One
controller's lines arrive in order, so anything no newer than a row's newest
moment has already been counted.

What isemon counted before this was switched on is not on the page. *Go back
over the logs* (Settings → Go back over the logs) reads the files that are
still on disk and fills in the days they cover.

The page is split into five pages, chosen by the buttons at its top:

- **Overview** (the default): a tile for each kind of trouble. Pressing a tile
  opens the machines or accounts behind it.
- **Machines** and **Accounts**: lists that can be searched by any of their
  columns, the same way as every other list (`machine:PC*`, `what:*LDAP*`,
  `-controller:pvtcdcx01`, `(a OR b)`).
- **Every row**: every finding, searchable the same way.
- **The logs and how to send them**.

**Export for analysis** (in the page's strip) saves one Markdown file. It
holds:

- the logs arriving;
- each kind of trouble, with what breaks and how to fix it;
- its rows, most first: 50, 100 or 250 of each kind;
- the worst machines and the worst accounts.

Account names, and machine names and addresses, can be put by stand-ins. The
file is made in the browser out of what is loaded, and is tens of kB.

Each list has a heading that stays put while its rows scroll, sorts by any
column over all of its rows, and uses the same pager as the other lists.
Pressing a row opens the events behind it.

## What the controllers have to send

The whole set-up - the domain policy (GPO) with PowerShell and the clicks
where PowerShell cannot do it, each controller, the complete `nxlog.conf`,
the checks, the risks and how to take it back - is in
`docs/active-directory-logging.md`. The short version follows.

The Security log is sent already and covers Kerberos, NTLMv1 and NTLM. The rest
need two steps.

### 1. On every domain controller

LDAP, so that the controller names who does it (2889, 3039). This takes effect
at once. At level 2 every such bind is an event, so on a busy controller keep
it on only for the weeks before the change:

```
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics" /v "16 LDAP Interface Events" /t REG_DWORD /d 2 /f
```

SMB1 to the controller (SMBServer/Audit, 3000):

```
Set-SmbServerConfiguration -AuditSmb1Access $true -Force
```

NTLM by server (NTLM/Operational, 8004): set a group policy on the Domain
Controllers OU. The path is Computer Configuration → Policies → Windows
Settings → Security Settings → Local Policies → Security Options. Set
*Network security: Restrict NTLM: Audit NTLM authentication in this domain*
to **Enable all**.

The Security log has to audit Kerberos and the logons, Success and Failure:

```
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
```

### 2. In nxlog.conf, beside the Security input

Add one input per log, so that a log a controller does not have does not
stop the others. All of them use the same output, so everything lands in the
file isemon already reads. Then run `Restart-Service nxlog`.

```
<Input eventlog_ds>
    Module          im_msvistalog
    SavePos         TRUE
    ReadFromLast    TRUE
    <QueryXML>
        <QueryList>
            <Query Id="0">
                <Select Path="Directory Service">*[System[(EventID=2886 or EventID=2887 or EventID=2888 or EventID=2889 or EventID=3039 or EventID=3040 or EventID=3041)]]</Select>
            </Query>
        </QueryList>
    </QueryXML>
</Input>

<Input eventlog_kdc>
    Module          im_msvistalog
    SavePos         TRUE
    ReadFromLast    TRUE
    <QueryXML>
        <QueryList>
            <Query Id="0">
                <Select Path="System">*[System[Provider[@Name='Microsoft-Windows-Kerberos-Key-Distribution-Center'] and (EventID=14 or EventID=16 or EventID=26 or EventID=27 or (EventID &gt;= 201 and EventID &lt;= 209))]]</Select>
            </Query>
        </QueryList>
    </QueryXML>
</Input>

<Input eventlog_smb1>
    Module          im_msvistalog
    SavePos         TRUE
    ReadFromLast    TRUE
    <QueryXML>
        <QueryList>
            <Query Id="0">
                <Select Path="Microsoft-Windows-SMBServer/Audit">*[System[(EventID=3000)]]</Select>
            </Query>
        </QueryList>
    </QueryXML>
</Input>

<Input eventlog_ntlm>
    Module          im_msvistalog
    SavePos         TRUE
    ReadFromLast    TRUE
    <QueryXML>
        <QueryList>
            <Query Id="0">
                <Select Path="Microsoft-Windows-NTLM/Operational">*[System[(EventID=8004)]]</Select>
            </Query>
        </QueryList>
    </QueryXML>
</Input>

<Route security_to_syslog>
    Path        eventlog_security, eventlog_ds, eventlog_kdc, eventlog_smb1, eventlog_ntlm => out_syslog
</Route>
```

The 2889 and 4769 events are often longer than 1500 bytes. Over UDP, losing
one fragment loses the whole event, so the TCP output already in the
configuration (port 514) is safer.
