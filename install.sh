#!/usr/bin/env bash
#
# install.sh — set up isemon on AlmaLinux 9 (and anything close enough).
#
# Packages, service user, configuration, systemd unit, log rotation, nginx
# with TLS, php-fpm, SELinux, firewall, the first account, and a check that it
# all works. Run it from inside the project folder, as root:
#
#     sudo ./install.sh
#
# Everything it asks can be given on the command line instead; --help lists
# the options. --dry-run prints what would happen and changes nothing.
# --upgrade replaces the program files and restarts, keeping the database,
# the configuration and the accounts. --uninstall removes the service and the
# dashboard but keeps everything recorded.
#
set -euo pipefail

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Read out of the program rather than written down here. Kept as its own
# line this said 1.10.43 while the program beside it was 1.10.58 - so an
# upgrade announced a version nobody was installing, and the one number a
# person checks afterwards was the wrong one. There is one place the version
# lives, and this is not it.
VERSION="$(sed -n "s/^__version__ = '\(.*\)'.*/\1/p" "$SOURCE_DIR/isemon.py" 2>/dev/null | head -n1)"
VERSION="${VERSION:-unknown}"
SERVICE_USER="isemon"
LIB_DIR="/usr/local/lib/isemon"
BIN_LINK="/usr/local/bin/isemon"
CONFIG_DIR="/etc/isemon"
CONFIG_FILE="$CONFIG_DIR/config.json"
STATE_DIR="/var/lib/isemon"
LOG_DIR="/var/log/isemon"
WEB_DIR="/var/www/isemon"
CERT_DIR="/etc/nginx/certs"
NGINX_CONF="/etc/nginx/conf.d/isemon.conf"
UNIT_FILE="/etc/systemd/system/isemon.service"
LOGROTATE_FILE="/etc/logrotate.d/isemon"
# The logs that ARRIVE here, which are somebody else's files: a rotation of
# their own, the permissions rsyslog gives new ones, and the daily tidy for
# what logrotate must not touch. See docs/log-rotation-and-permissions.md.
REMOTE_LOGROTATE_FILE="/etc/logrotate.d/remote-logs"
RSYSLOG_PERMS_FILE="/etc/rsyslog.d/00-isemon-permissions.conf"
TIDY_CRON_FILE="/etc/cron.daily/isemon-logs-tidy"
RSYSLOG_FILE="/etc/rsyslog.d/10-ise.conf"
# What the pages may ask of root (1.10.222): the web server and the firewall
# (isemon_web.py), and a new version (isemon_upgrade.py). Each is a systemd
# path unit watching a folder of the daemon's for a request, and a oneshot
# service that runs the helper as root when one appears.
WEB_PATH_UNIT="/etc/systemd/system/isemon-web.path"
WEB_SERVICE_UNIT="/etc/systemd/system/isemon-web.service"
UPGRADE_PATH_UNIT="/etc/systemd/system/isemon-upgrade.path"
UPGRADE_SERVICE_UNIT="/etc/systemd/system/isemon-upgrade.service"
# The console at login (1.10.228): the profile script, and root's choice,
# kept in /etc itself where only root writes.
CONSOLE_PROFILE="/etc/profile.d/zz-isemon-console.sh"
CONSOLE_FLAG="/etc/isemon-console-login"

DRY_RUN=""
ASSUME_YES=""
WITH_WEB="yes"
WITH_SYSLOG="yes"
PHP_UPDATE="yes"         # --no-php-update: the PHP of the pages left as it is
PYTHON_UPDATE="yes"      # --no-python-update: isemon stays on the Python it runs on
# Asked for by name. A plain --upgrade changes nothing of how the logs are
# received or what PostgreSQL lets this program do (1.10.202): a machine
# where that already works is left exactly as it is. A fresh install does
# both; an upgrade does them only with --with-syslog / --db-rights.
SYSLOG_ASKED=""
WITH_DB=""
DB_RESTART="yes"
DO_UPGRADE=""
DO_UNINSTALL=""
DO_DB_RIGHTS=""

SERVER_NAME="blacklistmt.example.loc"
ALLOW_FROM=""
LOG_FROM=""
ISE_PATHS="/var/log/remote/ise1,/var/log/remote/ise2"
WATCH_DEVICES="FTD-VPN"
NEVER_BLOCK=""
MIKROTIK_HOST=""
MIKROTIK_USER="isemon"
MIKROTIK_LIST="isemon"
ADMIN_USER="admin"
ADMIN_PASSWORD=""
CERT_FILE=""
KEY_FILE=""

# ---------------------------------------------------------------------------
# Saying things
# ---------------------------------------------------------------------------
if [[ -t 1 ]]; then
    C_HEAD=$'\033[1;36m'; C_OK=$'\033[32m'; C_WARN=$'\033[33m'
    C_BAD=$'\033[1;31m'; C_DIM=$'\033[2m'; C_OFF=$'\033[0m'
else
    C_HEAD=""; C_OK=""; C_WARN=""; C_BAD=""; C_DIM=""; C_OFF=""
fi
step()  { printf '\n%s==> %s%s\n' "$C_HEAD" "$1" "$C_OFF"; }
say()   { printf '    %s\n' "$1"; }
note()  { printf '    %s%s%s\n' "$C_DIM" "$1" "$C_OFF"; }
good()  { printf '    %s%s%s\n' "$C_OK" "$1" "$C_OFF"; }
warn()  { printf '    %s%s%s\n' "$C_WARN" "$1" "$C_OFF"; }
fail()  { printf '\n%sERROR: %s%s\n' "$C_BAD" "$1" "$C_OFF" >&2; exit 1; }

run() {
    if [[ -n "$DRY_RUN" ]]; then
        note "[would run] $*"
        return 0
    fi
    "$@"
}

# One of the files under deploy/ put in place with the daemon's own account
# written into it. They are shipped saying `isemon` because that is what the
# account is called on every machine that has not been told otherwise, and a
# file somebody copies by hand should be right as it stands; this is for the
# machine where it is called something else.
install_substituted() {     # install_substituted SRC DEST MODE
    local src="$1" dest="$2" mode="${3:-0644}"
    if [[ -n "$DRY_RUN" ]]; then
        note "[would install] $dest (mode $mode, group $SERVICE_USER)"
        return 0
    fi
    install -D -m "$mode" /dev/null "$dest"
    sed -e "s/\broot isemon\b/root $SERVICE_USER/g" \
        -e "s/^\$FileGroup      isemon$/\$FileGroup      $SERVICE_USER/" \
        -e "s/^\$DirGroup       isemon$/\$DirGroup       $SERVICE_USER/" \
        "$src" > "$dest"
}

write_file() {      # write_file DEST MODE < content
    local dest="$1" mode="${2:-0644}" body
    body="$(cat)"
    if [[ -n "$DRY_RUN" ]]; then
        note "[would write] $dest (${#body} bytes, mode $mode)"
        return 0
    fi
    install -D -m "$mode" /dev/null "$dest"
    printf '%s\n' "$body" > "$dest"
}

# Root does not follow a link somebody else could have put there. The
# daemon's own folders are writable by its account, and a link planted in
# one of them (config.json -> /etc/shadow, dumps -> /etc/sudoers.d) made the
# next run of this, as root, hand that file or folder to the daemon.
# How far an upgrade is, for the bar on the page (1.10.222): said only when
# install.sh was started from the pages (isemon_upgrade.py reads it).
UP_STEPS=8
progress() {        # progress N "words"
    [[ -n "${ISEMON_UPGRADE_FROM_PAGES:-}" ]] && printf '@@progress %d/%d %s\n' "$1" "$UP_STEPS" "$2"
    return 0
}

# Root's half of what the pages may ask (1.10.222): the two helpers, the
# release keys a package from the pages must be signed with, the four units
# and the two folders they watch. Nothing here changes nginx, the firewall
# or the program: the units do nothing until the daemon lays a request down,
# and the daemon does that only when somebody saves something on the
# Firewall and access, Certificates and TLS or Upgrades panes.
root_helpers() {
    step "What the pages may ask of root"
    local k
    not_a_link "$STATE_DIR" "$STATE_DIR/web" "$STATE_DIR/upgrade"
    run install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$STATE_DIR/web"
    run install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$STATE_DIR/upgrade"
    run install -D -m 0755 -o root -g root "$SOURCE_DIR/deploy/isemon_web.py" "$LIB_DIR/isemon_web.py"
    run install -D -m 0755 -o root -g root "$SOURCE_DIR/deploy/isemon_upgrade.py" "$LIB_DIR/isemon_upgrade.py"
    run install -d -m 0755 -o root -g root "$LIB_DIR/release-keys"
    for k in "$SOURCE_DIR"/deploy/release-keys/*.pub; do
        [[ -f "$k" ]] && run install -m 0644 -o root -g root "$k" "$LIB_DIR/release-keys/"
    done
    # Only the keys this package ships are trusted from now on: a package is
    # signed by its own release's key, and an old key nobody uses any more is
    # one fewer way in.
    if compgen -G "$SOURCE_DIR/deploy/release-keys/*.pub" >/dev/null; then
        for k in "$LIB_DIR"/release-keys/*.pub; do
            [[ -f "$k" && ! -f "$SOURCE_DIR/deploy/release-keys/$(basename "$k")" ]] && run rm -f "$k"
        done
    fi
    run install -D -m 0644 "$SOURCE_DIR/deploy/isemon-web.service" "$WEB_SERVICE_UNIT"
    run install -D -m 0644 "$SOURCE_DIR/deploy/isemon-web.path" "$WEB_PATH_UNIT"
    run install -D -m 0644 "$SOURCE_DIR/deploy/isemon-upgrade.service" "$UPGRADE_SERVICE_UNIT"
    run install -D -m 0644 "$SOURCE_DIR/deploy/isemon-upgrade.path" "$UPGRADE_PATH_UNIT"
    run systemctl daemon-reload
    # The upgrade's own path unit is not restarted while it is the one
    # running this (an upgrade from the pages): it is already watching.
    if [[ -z "${ISEMON_UPGRADE_FROM_PAGES:-}" ]]; then
        run systemctl enable isemon-upgrade.path >/dev/null 2>&1 || true
        run systemctl restart isemon-upgrade.path >/dev/null 2>&1 \
            || warn "isemon-upgrade.path did not start; upgrades from the pages wait for it"
    else
        run systemctl enable isemon-upgrade.path >/dev/null 2>&1 || true
    fi
    { run systemctl enable isemon-web.path >/dev/null 2>&1 && run systemctl restart isemon-web.path >/dev/null 2>&1; } \
        || warn "isemon-web.path did not start; the firewall and TLS from the pages wait for it"
    good "the firewall, TLS, system updates and upgrades from the pages: isemon-web.path, isemon-upgrade.path"
    good "packages from the pages must be signed by: $(ls "$LIB_DIR/release-keys" 2>/dev/null | sed 's/\.pub$//' | paste -sd, -)"
}

# A package put in when it is missing (1.10.236): on an install and on
# every upgrade alike. Only ever adds - nothing already installed is changed,
# upgraded or taken away - and a package that cannot be had (no repository,
# no network) is said and the rest goes on.
PKG_UPDATED=""
PKG_UNTIL=""        # all of it within ten minutes: an upgrade has a deadline
pkg_add() {         # pkg_add <rpm> <deb>
    if [[ -n "$DRY_RUN" ]]; then note "[would install] ${1}"; return 0; fi
    if [[ -n "$PKG_UNTIL" ]] && (( SECONDS > PKG_UNTIL )); then return 0; fi
    if [[ "$PKG" == "dnf" ]]; then
        timeout 300 dnf install -y "$1" >/dev/null 2>&1 || true
    elif [[ "$PKG" == "apt" ]]; then
        if [[ -z "$PKG_UPDATED" ]]; then
            timeout 300 apt-get update >/dev/null 2>&1 || true
            PKG_UPDATED=1
        fi
        DEBIAN_FRONTEND=noninteractive timeout 300 apt-get install -y "$2" >/dev/null 2>&1 || true
    fi
}

tool_add() {        # tool_add <program> <rpm> <deb> "what it is for"
    if command -v "$1" >/dev/null 2>&1; then return 0; fi
    [[ -n "$PKG" ]] || { warn "$1 is missing ($4) - install $2 by hand"; return 0; }
    pkg_add "$2" "$3"
    if [[ -n "$DRY_RUN" ]] || command -v "$1" >/dev/null 2>&1; then
        good "$([[ "$PKG" == "apt" ]] && echo "$3" || echo "$2") installed - $4"
    else
        warn "$([[ "$PKG" == "apt" ]] && echo "$3" || echo "$2") could not be installed - $4 ($PKG install it by hand)"
    fi
}

# What isemon uses beside Python, put in whenever it is missing. The
# database's driver and client too, for the engine config.json names.
ensure_packages() {     # ensure_packages fresh|upgrade
    local ssh_pkg="openssh-clients" smb_pkg="samba-client"
    PKG_UNTIL=$((SECONDS + 600))
    [[ "$PKG" == "apt" ]] && { ssh_pkg="openssh-client"; smb_pkg="smbclient"; }
    tool_add ssh        "$ssh_pkg" "$ssh_pkg" "the ssh client (routers, backups over SFTP and SCP)"
    tool_add ssh-keygen "$ssh_pkg" "$ssh_pkg" "ssh keys"
    tool_add setfacl    acl acl "the rights on the logs"
    tool_add openssl    openssl openssl "signed packages, locked backups, certificates"
    tool_add smbclient  "$smb_pkg" "$smb_pkg" "backups to a Windows or Samba share"
    # chrony put in now is started below; one an admin switched off is not.
    command -v chronyc >/dev/null 2>&1 || CHRONY_NEW=1
    # On Debian chrony takes the place of timesyncd or ntp: not where one runs.
    if [[ "$PKG" != "apt" ]] || ! time_kept_by >/dev/null; then
        tool_add chronyc    chrony chrony "Settings -> Time reads the clock through chrony"
    fi
    if [[ -f "$WEB_DIR/index.php" || ( "$1" == "fresh" && -n "$WITH_WEB" ) ]]; then
        tool_add nginx nginx nginx "the web server of the pages"
        command -v php-fpm >/dev/null 2>&1 || php-fpm -v >/dev/null 2>&1 \
            || ls /usr/sbin/php*-fpm* >/dev/null 2>&1 || tool_add php-fpm php-fpm php-fpm "the pages' PHP"
        tool_add php php-cli php-cli "the pages' PHP on the command line"
    fi
    # The otp logs over TLS (1.10.245): rsyslog's TLS driver - gnutls, the one
    # otp's README names - where rsyslog is and the driver is not.
    if command -v rsyslogd >/dev/null 2>&1 && [[ -n "$PKG" ]] && \
            ! ls /usr/lib64/rsyslog/lmnsd_gtls.so /usr/lib/rsyslog/lmnsd_gtls.so \
                 /usr/lib/*-linux-gnu/rsyslog/lmnsd_gtls.so >/dev/null 2>&1; then
        pkg_add rsyslog-gnutls rsyslog-gnutls
        ls /usr/lib64/rsyslog/lmnsd_gtls.so /usr/lib/rsyslog/lmnsd_gtls.so \
           /usr/lib/*-linux-gnu/rsyslog/lmnsd_gtls.so >/dev/null 2>&1 \
            && good "rsyslog-gnutls installed - the otp logs can arrive over TLS"
    fi
    # colorama makes the colours of the command line right everywhere;
    # nothing needs it - without it isemon writes the escapes itself.
    if ! python3 -c 'import colorama' 2>/dev/null && [[ -n "$PKG" ]]; then
        pkg_add python3-colorama python3-colorama
        python3 -c 'import colorama' 2>/dev/null && good "python3-colorama installed - the command line in colour"
    fi
    # The engine this machine is set to use (an upgrade): its driver and its
    # dump program, when they went missing.
    if [[ "$1" == "upgrade" && -z "${WITH_DB:-}" && -f "$CONFIG_FILE" ]]; then
        local engine
        engine="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("db_engine") or "")' "$CONFIG_FILE" 2>/dev/null)"
        case "$engine" in
            mariadb|mysql)
                python3 -c 'import pymysql' 2>/dev/null || db_driver "MariaDB" pymysql python3-PyMySQL PyMySQL
                command -v mariadb-dump >/dev/null 2>&1 || db_client "MariaDB" mariadb-dump mariadb default-mysql-client;;
            postgres|postgresql)
                python3 -c 'import psycopg2' 2>/dev/null || db_driver "PostgreSQL" psycopg2 python3-psycopg2 psycopg2-binary
                command -v pg_dump >/dev/null 2>&1 || db_client "PostgreSQL" pg_dump postgresql postgresql-client;;
        esac
    fi
    return 0
}

# The clock (1.10.228): Settings -> Time reads it through chrony, put in
# above when it was missing. chronyd is started when it is not running - the
# way AlmaLinux has it out of the box - unless something else keeps the time
# (systemd-timesyncd, ntpd, openntpd): a machine that keeps its time some
# other way keeps it so.
CHRONY_NEW=""
time_kept_by() {    # prints the service that keeps the time, if any but chronyd
    local u
    for u in systemd-timesyncd ntpd ntp ntpsec openntpd ptp4l phc2sys; do
        if systemctl is-active --quiet "$u" 2>/dev/null; then echo "$u"; return 0; fi
    done
    return 1
}

chrony_check() {    # chrony_check fresh|upgrade
    [[ -n "$DRY_RUN" ]] && return 0
    command -v chronyd >/dev/null 2>&1 || return 0
    # Not running - installed just now (its package marks it enabled, and
    # starts nothing), or enabled and never started: started. One an admin
    # disabled or masked is left so (1.10.238), and said.
    if ! systemctl is-active --quiet chronyd 2>/dev/null; then
        local other="" state
        other="$(time_kept_by)"
        state="$(systemctl is-enabled chronyd 2>/dev/null)"
        if [[ -z "$CHRONY_NEW" && "$1" == "upgrade" && "$state" != "enabled" ]]; then
            note "chronyd is $state here - left so; Settings -> Time can start it"
        elif [[ -z "$other" ]]; then
            run systemctl enable --now chronyd >/dev/null 2>&1 || true
            systemctl is-active --quiet chronyd 2>/dev/null && good "chronyd started - the clock is kept by chrony"
        else
            note "the time is kept by $other here: chronyd is left off, Settings -> Time says so"
        fi
    fi
    if ! systemctl is-active --quiet chronyd 2>/dev/null; then
        note "chronyd is not running here: Settings -> Time shows the clock as chrony sees it,"
        note "  and says what it can without it (systemctl enable --now chronyd)"
    fi
    return 0
}

# The isemon console at login (1.10.228), as otp's: root signing in at the
# console or over SSH lands in `isemon --console`, and q leaves it for the
# shell. The profile script is put in on every run and does nothing without
# the choice file; the choice is written on a fresh install only. An upgrade
# never makes it or changes it, so a plain upgrade changes nothing about
# root's login (`isemon --console-at-login on` switches it on there).
install_console() {        # install_console fresh|upgrade
    run install -D -m 0644 "$SOURCE_DIR/deploy/isemon-console-login.sh" "$CONSOLE_PROFILE"
    [[ "$1" == "fresh" ]] || return 0
    if [[ -n "$DRY_RUN" ]]; then note "[would write] $CONSOLE_FLAG"; return 0; fi
    # A link or anything else that is not a plain file is taken away, never
    # followed; a choice already made (a reinstall) is left as it is.
    if [[ -L "$CONSOLE_FLAG" || ( -e "$CONSOLE_FLAG" && ! -f "$CONSOLE_FLAG" ) ]]; then
        rm -f "$CONSOLE_FLAG"
    fi
    if [[ ! -f "$CONSOLE_FLAG" ]]; then
        printf 'on\n' > "$CONSOLE_FLAG.$$" && chmod 0644 "$CONSOLE_FLAG.$$" \
            && mv -f "$CONSOLE_FLAG.$$" "$CONSOLE_FLAG"
    fi
    good "the isemon console at login: $(head -c 3 "$CONSOLE_FLAG" 2>/dev/null | tr -cd 'onf') (isemon --console-at-login on|off)"
}

not_a_link() {      # not_a_link PATH...
    local one
    for one in "$@"; do
        [[ -L "$one" ]] && fail "$one is a symbolic link, which it never should be here; look at it before running this again"
    done
    return 0
}

# A comma separated list of addresses or networks, every one of them checked.
cidr_list_ok() {    # cidr_list_ok "a,b,c"
    python3 - "$1" <<'PY'
import ipaddress, sys
bad = []
for one in sys.argv[1].split(','):
    one = one.strip()
    if not one:
        continue
    try:
        ipaddress.ip_network(one, strict=False)
    except ValueError:
        bad.append(one)
if bad:
    sys.stderr.write('not an address or a network: %s\n' % ', '.join(bad))
    sys.exit(1)
PY
}

# Which accounts the web server runs as: what php-fpm is set to run as, and
# the usual names, those that exist.
find_web_users() {
    local conf who maybe list=""
    for conf in /etc/php-fpm.d/www.conf /etc/php/*/fpm/pool.d/www.conf; do
        [[ -r "$conf" ]] || continue
        who="$(sed -n 's/^[[:space:]]*user[[:space:]]*=[[:space:]]*\([^[:space:];]*\).*/\1/p' \
               "$conf" | head -1)"
        [[ -n "$who" ]] && list="$list $who"
    done
    for maybe in nginx www-data apache httpd; do
        list="$list $maybe"
    done
    WEB_USERS=""
    for who in $list; do
        id "$who" >/dev/null 2>&1 || continue
        case " $WEB_USERS " in *" $who "*) continue;; esac
        WEB_USERS="$WEB_USERS $who"
    done
}

# The web server's accounts in a group of their own, which is for reading the
# API token and nothing else (`isemon-web`). They used to be put in the
# daemon's own group - the group of its database, its backups and its
# configuration with the database password in it - so every PHP site on the
# machine could read all of that. The daemon is in this group too, so that
# it can give the token to it.
WEB_GROUP="${SERVICE_USER}-web"
web_group_setup() {
    find_web_users
    getent group "$WEB_GROUP" >/dev/null || run groupadd --system "$WEB_GROUP"
    run usermod -a -G "$WEB_GROUP" "$SERVICE_USER"
    local who
    for who in $WEB_USERS; do
        run usermod -a -G "$WEB_GROUP" "$who"
    done
    if [[ -n "$WEB_USERS" ]]; then
        good "these may read the API token, through $WEB_GROUP:$WEB_USERS"
    else
        warn "no web server account was found to put in $WEB_GROUP"
    fi
}

# ...and, once the daemon is running and the token IS the web group's, out of
# the daemon's own group - one at a time, and only an account that can read
# the token without it. Until then nothing is taken away, so a machine where
# something is different keeps working exactly as it did.
web_group_tighten() {
    [[ -n "$DRY_RUN" ]] && return 0
    local token=/run/isemon/api-token who taken=""
    [[ -f "$token" ]] || return 0
    [[ "$(stat -c %G "$token" 2>/dev/null)" == "$WEB_GROUP" ]] || {
        note "the API token is not in $WEB_GROUP yet; the web accounts keep the $SERVICE_USER group"
        return 0
    }
    for who in $WEB_USERS; do
        id -nG "$who" 2>/dev/null | tr ' ' '\n' | grep -qx "$SERVICE_USER" || continue
        id -nG "$who" 2>/dev/null | tr ' ' '\n' | grep -qx "$WEB_GROUP" || continue
        gpasswd -d "$who" "$SERVICE_USER" >/dev/null 2>&1 || continue
        # ...and put straight back if the token is not readable without it:
        # whatever is different on this machine, the page keeps working.
        if runuser -u "$who" -- test -r "$token" 2>/dev/null; then
            taken="$taken $who"
        else
            usermod -a -G "$SERVICE_USER" "$who" 2>/dev/null || true
            note "$who still needs the $SERVICE_USER group to read the token; it was left in it"
        fi
    done
    if [[ -n "$taken" ]]; then
        good "no longer in the $SERVICE_USER group (they read the token through $WEB_GROUP):$taken"
        for unit in $(php_fpm_units); do
            systemctl restart "$unit" || warn "$unit would not restart"
        done
    fi
}

# php2shell (CVE-2026-109618, CVE-2026-109619; 1.10.218): the dashboard's vhost
# refuses multipart bodies, which PHP takes apart before any of the page runs.
# A vhost of the site's own is otherwise never touched here; this one rule is
# put into it - the file kept beside it first, nginx asked whether it still
# reads, and put back as it was if not.
nginx_php2shell_guard() {
    [[ -f "$NGINX_CONF" ]] || return 0
    if grep -qiE 'content_type[^;]*multipart' "$NGINX_CONF"; then
        good "$NGINX_CONF refuses multipart bodies (php2shell)"
        return 0
    fi
    if [[ -n "$DRY_RUN" ]]; then
        note "[would add] the multipart rule against php2shell to $NGINX_CONF"
        return 0
    fi
    local keep="$NGINX_CONF.before-php2shell"
    cp -a "$NGINX_CONF" "$keep" || { warn "could not keep a copy of $NGINX_CONF"; return 0; }
    if ! python3 - "$NGINX_CONF" <<'PY'
import re, sys
path = sys.argv[1]
text = open(path).read()
rule = ('{i}# php2shell (CVE-2026-109618, CVE-2026-109619): nothing on the isemon page\n'
        '{i}# sends a multipart body, and PHP takes one apart before the page runs.\n'
        '{i}if ($http_content_type ~* "multipart") {{ return 403; }}\n')
# After the line refusing other methods, where the shipped file has it; else
# after the body size limit; else at the top of the TLS server block.
for pattern in (r'(?m)^([ \t]*)if \(\$request_method[^\n]*\n',
                r'(?m)^([ \t]*)client_max_body_size[^\n]*\n',
                r'(?m)^([ \t]*)listen[ \t]+(?:\[::\]:)?443[^\n]*\n'):
    m = re.search(pattern, text)
    if m:
        text = text[:m.end()] + rule.format(i=m.group(1) or '    ') + text[m.end():]
        open(path, 'w').write(text)
        sys.exit(0)
sys.exit(1)
PY
    then
        warn "$NGINX_CONF: no place found for the multipart rule against php2shell; add"
        warn "  inside its server { } block:  if (\$http_content_type ~* \"multipart\") { return 403; }"
        rm -f "$keep"
        return 0
    fi
    if command -v nginx >/dev/null && ! nginx -t >/dev/null 2>&1; then
        cp -a "$keep" "$NGINX_CONF"
        warn "$NGINX_CONF did not read with the multipart rule added, so it was put back"
        warn "  as it was; add inside its server { } block by hand:"
        warn "  if (\$http_content_type ~* \"multipart\") { return 403; }"
        return 0
    fi
    good "$NGINX_CONF refuses multipart bodies now (php2shell); the one before is $keep"
    command -v nginx >/dev/null && systemctl reload nginx 2>/dev/null || true
}

# What the PHP serving the page says of itself against php2shell.
php2shell_said() {
    local php_bin
    php_bin="$(command -v php || true)"
    [[ -n "$php_bin" ]] || return 0
    local v
    v="$("$php_bin" -r 'echo PHP_VERSION;' 2>/dev/null || true)"
    [[ -n "$v" ]] || return 0
    if "$php_bin" -r '$f=["8.2"=>"8.2.35","8.3"=>"8.3.36","8.4"=>"8.4.27","8.5"=>"8.5.12"];
            $b=PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;
            exit(isset($f[$b]) ? (version_compare(PHP_VERSION,$f[$b],">=")?0:1)
                               : (version_compare($b,"8.5",">")?0:1));' 2>/dev/null; then
        good "PHP $v has the php2shell fix (CVE-2026-109618, CVE-2026-109619)"
    else
        warn "PHP $v may have php2shell (CVE-2026-109618, CVE-2026-109619): remote code"
        warn "  execution by anybody who reaches the web server. Update PHP - 8.2.35, 8.3.36,"
        warn "  8.4.27, 8.5.12 or later, or your distribution's fixed package"
        warn "  (dnf update 'php*' / apt upgrade) - and restart php-fpm. The dashboard is"
        warn "  guarded meanwhile (web/.user.ini, and the multipart rule in nginx); also set"
        warn "  session.upload_progress.enabled = 0 in /etc/php.d - see docs/php2shell.md."
    fi
}

# The PHP of the pages moved to a release with the php2shell fix (1.10.250):
# 8.3.36 - or 8.4.27 / 8.5.12 where the machine is on those already. The
# RHEL family backports the fix and keeps the old number (8.3.8 ...), so the
# upstream release comes from the Remi repository (php:remi-8.3, which needs
# EPEL): the module stream switched, what Remi offers checked to be the fixed
# release BEFORE a package is changed, then `dnf distro-sync 'php*'` - every
# PHP package there is, to Remi's build of it; the configuration is kept
# (rpm leaves php.ini and php-fpm.d as they are). php-fpm restarted and asked
# its version; anything that does not work and the stream it was on is put
# back. --no-php-update leaves PHP alone; Debian and Ubuntu are said, not
# changed.
PHP_TARGET="8.3"
php_fix_of() {        # php_fix_of 8.3 -> 8.3.36
    case "$1" in
        8.2) echo 8.2.35;; 8.3) echo 8.3.36;; 8.4) echo 8.4.27;; 8.5) echo 8.5.12;; *) echo "";;
    esac
}
version_ge() {        # version_ge A B: A >= B
    [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" == "$2" ]]
}
php_now() {          # the PHP of the pages: php's, else php-fpm's own (1.10.254)
    local v="" f
    if command -v php >/dev/null 2>&1; then
        v="$(php -r 'echo PHP_VERSION;' 2>/dev/null || true)"
    fi
    if [[ -z "$v" ]]; then
        for f in php-fpm /usr/sbin/php-fpm; do
            command -v "$f" >/dev/null 2>&1 || continue
            v="$("$f" -v 2>/dev/null | sed -n 's/^PHP \([0-9][0-9.]*\).*/\1/p' | head -1 || true)"
            [[ -n "$v" ]] && break
        done
    fi
    echo "$v"
}
php_is_fixed() {      # php_is_fixed VERSION
    local mm fix
    mm="$(echo "$1" | cut -d. -f1,2)"
    fix="$(php_fix_of "$mm")"
    [[ -n "$fix" ]] && version_ge "$1" "$fix" && return 0
    [[ -z "$fix" ]] && version_ge "$mm" "8.6" && return 0
    return 1
}
php_fpm_restart() {
    local u
    for u in $(php_fpm_units); do
        systemctl restart "$u" 2>/dev/null || return 1
    done
    return 0
}
php_stream_back() {   # php_stream_back STREAM - the stream it was on, and its packages
    timeout 120 dnf -y -q module reset php >/dev/null 2>&1 || true
    [[ -n "$1" ]] && timeout 120 dnf -y -q module enable "php:$1" >/dev/null 2>&1 || true
}
# One stream tried (1.10.253, 1.10.254): enabled, what it offers looked at
# before a package is changed - PHP $target, MIN or later (later than MIN
# when STRICT) - every PHP package moved to it, php-fpm restarted and asked.
# The stream and the PHP it was on are put back when anything does not work.
# Called in an `if`, and every pipeline ends in `|| true`: install.sh runs
# under set -e, and a dnf that lists nothing must not end the upgrade.
php_try() {           # php_try STREAM TARGET MIN STRICT WAS UNTIL
    local stream="$1" target="$2" min="$3" strict="$4" was="$5" until="$6" avail now
    timeout 120 dnf -y -q module reset php >/dev/null 2>&1 || true
    if ! timeout 300 dnf -y -q module enable "php:$stream" >/dev/null 2>&1; then
        php_stream_back "$was"
        PHP_SAID="the stream php:$stream could not be enabled"
        return 1
    fi
    avail="$(timeout 300 dnf -q repoquery --latest-limit=1 --qf '%{version}' php-fpm 2>/dev/null \
             | grep -E '^[0-9]+\.[0-9]+\.[0-9]+' | sort -V | tail -1 || true)"
    if [[ -z "$avail" || "$(echo "$avail" | cut -d. -f1,2)" != "$target" ]] \
            || ! version_ge "$avail" "$min" || { [[ -n "$strict" ]] && [[ "$avail" == "$min" ]]; }; then
        php_stream_back "$was"
        PHP_SAID="php:$stream offers PHP ${avail:-nothing}"
        return 1
    fi
    if (( SECONDS + 240 > until )); then
        php_stream_back "$was"
        PHP_SAID="the repositories were slow to answer - run the upgrade again"
        return 1
    fi
    if ! timeout $((until - SECONDS)) dnf -y -q distro-sync 'php*' >/dev/null 2>&1; then
        php_stream_back "$was"
        timeout 600 dnf -y -q distro-sync 'php*' >/dev/null 2>&1 || true
        php_fpm_restart || true
        PHP_SAID="dnf could not move PHP to $avail (php:$stream): back on $(php_now)"
        return 1
    fi
    now="$(php_now)"
    if [[ "$(echo "$now" | cut -d. -f1,2)" != "$target" ]] || ! version_ge "$now" "$min" \
            || ! php_fpm_restart; then
        php_stream_back "$was"
        timeout 600 dnf -y -q distro-sync 'php*' >/dev/null 2>&1 || true
        php_fpm_restart || true
        PHP_SAID="PHP $now (php:$stream) did not start as it should: back on $(php_now)"
        return 1
    fi
    PHP_SAID="$now"
    return 0
}
# The PHP of the pages to PHP 8.3 (1.10.250, 1.10.254), on every upgrade:
#   1. Remi's 8.3 (EPEL and Remi added) - the release with the php2shell fix,
#      8.3.36, or else the newest 8.3 Remi has, when it is newer than what
#      runs;
#   2. else the distribution's own php:8.3 (AlmaLinux / RHEL AppStream, the
#      fix backported under its own number), for a PHP older than 8.3;
#   3. a PHP 8.3 there already: its stream brought up to date (dnf upgrade).
# Never down: 8.4 and 8.5 stay on their line. Every step says what it found.
php_update() {
    [[ -n "$PHP_UPDATE" ]] || { note "PHP: --no-php-update - left as it is"; return 0; }
    local v mm target fix el was remi=""
    v="$(php_now)"
    if [[ -z "$v" ]]; then
        note "PHP: neither php nor php-fpm answers here - nothing to move"
        return 0
    fi
    if php_is_fixed "$v"; then
        good "PHP $v has the php2shell fix - left as it is"
        return 0
    fi
    mm="$(echo "$v" | cut -d. -f1,2)"
    target="$PHP_TARGET"
    case "$mm" in 8.4|8.5) target="$mm";; esac
    fix="$(php_fix_of "$target")"
    if [[ -n "$DRY_RUN" ]]; then
        note "[would move] PHP $v to PHP $target - Remi's ($fix or the newest there), else the distribution's php:$target"
        return 0
    fi
    if [[ "$PKG" != "dnf" ]]; then
        warn "PHP $v: update it to $target by hand - your distribution's package, or"
        warn "  ppa:ondrej/php / packages.sury.org - then restart php-fpm"
        return 0
    fi
    el="$(rpm -E '%rhel' 2>/dev/null || true)"
    if [[ ! "$el" =~ ^(8|9|10)$ ]]; then
        warn "PHP $v: not a RHEL 8, 9 or 10 here - update PHP by hand"
        return 0
    fi
    say "PHP $v runs the pages: to PHP $target ($fix has the php2shell fix)"
    # An upgrade from the pages has 25 minutes in all: the move and a way back
    # in what is left of 15 of them.
    local until=$((SECONDS + 900))
    was="$(timeout 120 dnf -q module list --enabled php 2>/dev/null | awk '$1=="php"{print $2; exit}' || true)"
    say "  the php stream enabled now: ${was:-none, the default PHP of the distribution}"
    PHP_SAID=""
    if ! rpm -q epel-release >/dev/null 2>&1; then
        timeout 300 dnf install -y -q epel-release >/dev/null 2>&1 || true
    fi
    if ! rpm -q remi-release >/dev/null 2>&1; then
        timeout 300 dnf install -y -q "https://rpms.remirepo.net/enterprise/remi-release-$el.rpm" \
            >/dev/null 2>&1 || true
    fi
    if rpm -q epel-release >/dev/null 2>&1 && rpm -q remi-release >/dev/null 2>&1; then
        remi=1
        say "  the EPEL and Remi repositories are there"
    else
        say "  the EPEL and Remi repositories could not be added (no way to them from here?)"
    fi
    if [[ -n "$remi" ]]; then
        if php_try "remi-$target" "$target" "$fix" "" "$was" "$until"; then
            good "PHP $PHP_SAID from the Remi repository (php:remi-$target) - php2shell fixed; php-fpm restarted"
            return 0
        fi
        say "  Remi, $fix or later: $PHP_SAID"
        # Not the fixed release yet: the newest 8.3 Remi has, newer than this.
        if [[ "$mm" == "$target" ]]; then
            php_try "remi-$target" "$target" "$v" 1 "$was" "$until" && {
                good "PHP $PHP_SAID from the Remi repository (php:remi-$target), php-fpm restarted"
                warn "  $PHP_SAID is not $fix yet: the next upgrade takes $fix when Remi has it"
                return 0; }
        elif php_try "remi-$target" "$target" "$target.0" "" "$was" "$until"; then
            good "PHP $PHP_SAID from the Remi repository (php:remi-$target), php-fpm restarted"
            warn "  $PHP_SAID is not $fix yet: the next upgrade takes $fix when Remi has it"
            return 0
        fi
        say "  Remi, the newest $target: $PHP_SAID"
    fi
    if ! version_ge "$mm" "$target"; then
        if php_try "$target" "$target" "$target.0" "" "$was" "$until"; then
            good "PHP $PHP_SAID from the distribution (php:$target), php-fpm restarted - its build carries"
            good "  the php2shell fix under its own number: dnf updateinfo list --cve CVE-2026-109618"
            return 0
        fi
        warn "PHP $v could not be moved to $target: $PHP_SAID"
        return 0
    fi
    # PHP 8.3 already, from the distribution: its newest build.
    timeout 600 dnf -y -q upgrade 'php*' >/dev/null 2>&1 || true
    php_fpm_restart || true
    good "PHP $(php_now) - PHP $mm brought up to date from its stream (${was:-default}); the"
    good "  distribution backports the php2shell fix: dnf updateinfo list --cve CVE-2026-109618"
    return 0
}

# The Python isemon runs on (1.10.252): the newest the distribution offers
# BESIDE its own - python3.14, 3.13, 3.12 or 3.11 on AlmaLinux / RHEL 9,
# whose own python3 is 3.9 and is dnf's: that one is never changed. A newer
# one is taken only when it imports what isemon needs (ssl, sqlite3 - and the
# database's driver, its package for that Python put in) and runs
# `isemon.py --version`; else the next older, else the one there is. What is
# chosen is LIB_DIR/python, a link every unit and the `isemon` command run
# through - put back by itself when isemon does not start on it.
PY_LINK="$LIB_DIR/python"
PY_BIN_DIR="${ISEMON_PY_BIN_DIR:-/usr/bin}"     # tests: a folder of their own
PY_WAS=""
PY_NEW=""
py_mm() { "$1" -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || true; }
py_fits() {           # py_fits BIN MM ENGINE
    local bin="$1" mm="$2" engine="$3"
    "$bin" -I -c 'import ssl, sqlite3, hashlib, json, socket, ipaddress, zlib' >/dev/null 2>&1 \
        || return 1
    case "$engine" in
        mariadb|mysql)
            "$bin" -c 'import pymysql' >/dev/null 2>&1 \
                || timeout 300 dnf install -y -q "python$mm-PyMySQL" >/dev/null 2>&1 || true
            "$bin" -c 'import pymysql' >/dev/null 2>&1 || return 1;;
        postgres|postgresql)
            "$bin" -c 'import psycopg2' >/dev/null 2>&1 \
                || timeout 300 dnf install -y -q "python$mm-psycopg2" >/dev/null 2>&1 || true
            "$bin" -c 'import psycopg2' >/dev/null 2>&1 || return 1;;
    esac
    "$bin" -I "$SOURCE_DIR/isemon.py" --version >/dev/null 2>&1 || return 1
    # The colours of the command line: nice, never needed.
    "$bin" -c 'import colorama' >/dev/null 2>&1 \
        || timeout 120 dnf install -y -q "python$mm-colorama" >/dev/null 2>&1 || true
    return 0
}
python_pick() {       # python_pick ENGINE - sets PY_WAS and PY_NEW
    local engine="$1" cur c bin
    cur="$(readlink -f "$PY_LINK" 2>/dev/null || true)"
    [[ -n "$cur" && -x "$cur" ]] || cur="$(command -v python3 || true)"
    PY_WAS="$cur"; PY_NEW="$cur"
    [[ -n "$PYTHON_UPDATE" && -n "$cur" ]] || return 0
    local now; now="$(py_mm "$cur")"
    if [[ "$PKG" != "dnf" ]]; then
        return 0            # Debian, Ubuntu: their own python3 is a recent one
    fi
    for c in 3.14 3.13 3.12 3.11; do
        version_ge "$now" "$c" && break        # nothing newer than what it runs on
        bin="$PY_BIN_DIR/python$c"
        if [[ -n "$DRY_RUN" ]]; then
            note "[would look for] python$c and run isemon on it when it fits"
            return 0
        fi
        if [[ ! -x "$bin" ]]; then
            timeout 300 dnf install -y -q "python$c" >/dev/null 2>&1 || continue
        fi
        [[ -x "$bin" ]] || continue
        if py_fits "$bin" "$c" "$engine"; then
            PY_NEW="$bin"
            break
        fi
        warn "python$c is there but does not run isemon here (a module, or the database's driver for it, is missing): an older one is looked for"
    done
    if [[ "$PY_NEW" == "$PY_WAS" ]]; then
        good "isemon runs on Python $now ($PY_WAS)"
    else
        good "isemon runs on Python $(py_mm "$PY_NEW") from now on ($PY_NEW; it was $now) - the system's python3 is as it was"
    fi
}
python_link() {       # LIB_DIR/python, and the isemon command through it
    [[ -n "$PY_NEW" ]] || PY_NEW="$(command -v python3)"
    run ln -sfn "$PY_NEW" "$PY_LINK"
    if [[ -n "$DRY_RUN" ]]; then
        note "[would write] $BIN_LINK, running $LIB_DIR/isemon.py on $PY_LINK"
        return 0
    fi
    rm -f "$BIN_LINK"
    printf '#!/bin/sh\n# isemon (1.10.252): the program, on the Python it is run on (%s).\nexec %s %s/isemon.py "$@"\n' \
        "$PY_LINK" "$PY_LINK" "$LIB_DIR" > "$BIN_LINK"
    chmod 0755 "$BIN_LINK"
}
python_back() {       # isemon did not start on the new one: the old one again
    [[ -n "$PY_WAS" && "$PY_NEW" != "$PY_WAS" ]] || return 1
    warn "isemon did not start on Python $(py_mm "$PY_NEW") - back on $(py_mm "$PY_WAS") ($PY_WAS)"
    run ln -sfn "$PY_WAS" "$PY_LINK"
    PY_NEW="$PY_WAS"
    run systemctl restart isemon.service
    sleep 2
    for _ in 1 2 3 4 5 6 7 8; do
        systemctl is-active --quiet isemon.service && return 0
        sleep 1
    done
    return 1
}
config_engine() {
    python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("db_engine") or "")' \
        "$CONFIG_FILE" 2>/dev/null || true
}

# The php-fpm units there are: php-fpm on the RHEL family, php8.2-fpm and
# the like on Debian and Ubuntu - which a restart of "php-fpm" never reached.
php_fpm_units() {
    local found="" unit
    if systemctl cat php-fpm.service >/dev/null 2>&1; then
        found="php-fpm"
    fi
    local listed
    listed="$(systemctl list-unit-files --no-legend 'php*-fpm.service' 2>/dev/null || true)"
    while read -r unit _rest; do
        unit="${unit%.service}"
        [[ -n "$unit" && "$unit" != "php-fpm" ]] || continue
        [[ "$unit" =~ ^php[0-9.]*-fpm$ ]] || continue
        found="$found $unit"
    done <<< "$listed"
    echo "$found"
}

ask() {          # ask VAR "prompt" "default"
    local var="$1" prompt="$2" default="${3:-}" answer
    if [[ -n "$ASSUME_YES" ]]; then
        printf -v "$var" '%s' "${!var:-$default}"
        return
    fi
    if [[ -n "${!var:-}" ]]; then default="${!var}"; fi
    if [[ -n "$default" ]]; then
        read -r -p "    $prompt [$default]: " answer
    else
        read -r -p "    $prompt: " answer
    fi
    printf -v "$var" '%s' "${answer:-$default}"
}

ask_secret() {
    local var="$1" prompt="$2" answer again
    [[ -n "$ASSUME_YES" ]] && return
    while true; do
        read -r -s -p "    $prompt: " answer; echo
        [[ -z "$answer" ]] && { printf -v "$var" '%s' ''; return; }
        if (( ${#answer} < 8 )); then
            warn "that is shorter than eight characters"
            continue
        fi
        read -r -s -p "    and again: " again; echo
        [[ "$answer" == "$again" ]] && { printf -v "$var" '%s' "$answer"; return; }
        warn "those two are not the same"
    done
}

confirm() {      # confirm "question" [default y|n]
    local default="${2:-y}" answer
    [[ -n "$ASSUME_YES" ]] && [[ "$default" == "y" ]] && return 0
    [[ -n "$ASSUME_YES" ]] && return 1
    read -r -p "    $1 [$( [[ $default == y ]] && echo Y/n || echo y/N )] " answer
    answer="${answer:-$default}"
    [[ "$answer" =~ ^[Yy] ]]
}

usage() {
    cat <<EOF
isemon installer $VERSION — a banning daemon for Cisco ISE

Usage: sudo ./install.sh [options]

  --server-name HOST      the dashboard's hostname (default $SERVER_NAME)
  --allow CIDR[,CIDR]     who may reach the dashboard at all (nginx allow rules)
  --ise-paths P[,P]       where the ISE logs land (default $ISE_PATHS)
  --watch-devices N[,N]   which NetworkDeviceName may earn a ban (default $WATCH_DEVICES)
  --never-block CIDR[,..] addresses nothing may ever ban — your own networks
  --mikrotik-host ADDR    the router, if there is one
  --mikrotik-user NAME    the account on it (default $MIKROTIK_USER)
  --mikrotik-list NAME    the address list it may touch (default $MIKROTIK_LIST)
  --admin-user NAME       the first dashboard account (default $ADMIN_USER)
  --admin-password PASS   its password (otherwise one is made and printed)
  --cert FILE --key FILE  TLS certificate and key to copy into $CERT_DIR
  --no-php-update         leave the PHP of the pages as it is. Otherwise a PHP
                          below the release that fixes php2shell (8.3.36, or
                          8.4.27 / 8.5.12 on those) is moved to PHP 8.3 from the
                          Remi repository (EPEL and Remi added), and back to
                          what it was if that does not work (RHEL family)
  --no-python-update      keep isemon on the Python it runs on. Otherwise the
                          newest Python the distribution offers beside its own
                          (python3.14 ... python3.11 on AlmaLinux / RHEL 9) is
                          put in and isemon run on it - when it imports what
                          isemon needs and starts; the system's python3 (dnf's)
                          is never changed
  --no-syslog             a fresh install: leave receiving the logs alone.
                          Otherwise rsyslog with its RELP and TLS modules is
                          installed where missing, what it makes under
                          /var/log/remote is readable by the daemon (permissions,
                          its umask, an ACL on what is there), the ISE receiver is
                          added where rsyslog does not listen already, and what
                          arrives is rotated where nothing rotates it already.
                          Nothing of the machine's own is replaced
  --with-syslog           with --upgrade: do the same on an installed machine
                          (a plain --upgrade never touches it)
  --log-from CIDR[,CIDR]  the machines that send their logs here (the ISE nodes,
                          NPS, ...): port 514 is opened to these alone. Without it
                          514 is opened to anybody who can reach this machine -
                          and anybody who can write to it can make a ban
  --with-db ENGINE        put the driver for a database server in place as well:
                          mariadb, postgres, or both. Nothing is configured and
                          nothing moves; this is so that Settings -> The database
                          has something to talk to the server with when you get
                          there. The file on this machine needs none of it.
  --no-web                daemon only, no dashboard and no nginx
  --no-db-restart         do not let the dashboard restart a PostgreSQL on this
                          machine after tuning it (the default lets it restart
                          PostgreSQL, and nothing else, through a polkit rule)

  --db-rights             let the dashboard tune and restart a PostgreSQL on this
                          machine without an administrator's password. On its own
                          it does only that; with --upgrade, the upgrade as well.
                          A fresh install does it; a plain --upgrade never does
  --upgrade               replace the program files and restart; keep everything else
  --uninstall             remove the service and the dashboard; keep the database
  --dry-run               print what would happen and change nothing
  --yes                   never ask; take the defaults
  --help                  this

Nothing it writes outside $LIB_DIR, $WEB_DIR and the three unit/config files
is ever replaced without saying so first.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --server-name)     SERVER_NAME="$2"; shift 2;;
        --allow)           ALLOW_FROM="$2"; shift 2;;
        --ise-paths)       ISE_PATHS="$2"; shift 2;;
        --watch-devices)   WATCH_DEVICES="$2"; shift 2;;
        --never-block)     NEVER_BLOCK="$2"; shift 2;;
        --mikrotik-host)   MIKROTIK_HOST="$2"; shift 2;;
        --mikrotik-user)   MIKROTIK_USER="$2"; shift 2;;
        --mikrotik-list)   MIKROTIK_LIST="$2"; shift 2;;
        --admin-user)      ADMIN_USER="$2"; shift 2;;
        --admin-password)  ADMIN_PASSWORD="$2"; shift 2;;
        --cert)            CERT_FILE="$2"; shift 2;;
        --key)             KEY_FILE="$2"; shift 2;;
        --with-syslog)     WITH_SYSLOG="yes"; SYSLOG_ASKED="yes"; shift;;
        --no-syslog)       WITH_SYSLOG=""; shift;;
        --no-php-update)   PHP_UPDATE=""; shift;;
        --no-python-update) PYTHON_UPDATE=""; shift;;
        --db-rights)       DO_DB_RIGHTS="yes"; shift;;
        --log-from)        LOG_FROM="$2"; shift 2;;
        --with-db)         WITH_DB="$2"
                           case "$WITH_DB" in
                               mariadb|mysql|postgres|postgresql|pgsql|both|all) ;;
                               *) fail "--with-db takes mariadb, postgres or both - not $WITH_DB";;
                           esac
                           shift 2;;
        --no-web)          WITH_WEB=""; shift;;
        --no-db-restart)   DB_RESTART=""; shift;;
        --upgrade)         DO_UPGRADE="yes"; shift;;
        --uninstall)       DO_UNINSTALL="yes"; shift;;
        --dry-run)         DRY_RUN="yes"; shift;;
        -y|--yes)          ASSUME_YES="yes"; shift;;
        -h|--help)         usage; exit 0;;
        *) fail "I do not know the option $1 — try --help";;
    esac
done

[[ $EUID -eq 0 ]] || fail "run this as root: sudo ./install.sh"
[[ -f "$SOURCE_DIR/isemon.py" ]] || fail "isemon.py is not beside this script; run it from inside the unpacked folder"

# ---------------------------------------------------------------------------
# Taking it away
# ---------------------------------------------------------------------------
if [[ -n "$DO_UNINSTALL" ]]; then
    step "Removing isemon $VERSION"
    say "The database, the configuration and the accounts are kept:"
    say "  $STATE_DIR  and  $CONFIG_DIR"
    confirm "Go ahead?" n || { say "Nothing was changed."; exit 0; }
    run systemctl disable --now isemon.service 2>/dev/null || true
    run systemctl disable --now isemon-web.path isemon-upgrade.path 2>/dev/null || true
    for one in "$UNIT_FILE" "$LOGROTATE_FILE" "$NGINX_CONF" "$BIN_LINK" \
               "$WEB_PATH_UNIT" "$WEB_SERVICE_UNIT" "$UPGRADE_PATH_UNIT" "$UPGRADE_SERVICE_UNIT" \
               "/etc/polkit-1/rules.d/49-isemon-database.rules" "$CONFIG_DIR/may-restart-database" \
               "$CONSOLE_PROFILE" "$CONSOLE_FLAG"; do
        [[ -e "$one" ]] && run rm -f "$one"
    done
    [[ -d "$LIB_DIR" ]] && run rm -rf "$LIB_DIR"
    [[ -d "$WEB_DIR" ]] && run rm -rf "$WEB_DIR"
    run systemctl daemon-reload
    command -v nginx >/dev/null && run systemctl reload nginx 2>/dev/null || true
    good "Gone. $STATE_DIR and $CONFIG_DIR were left alone."
    left=""
    for one in "$RSYSLOG_PERMS_FILE" "$RSYSLOG_FILE" "$REMOTE_LOGROTATE_FILE" "$TIDY_CRON_FILE" \
               "/etc/systemd/system/rsyslog.service.d/isemon-umask.conf"; do
        [[ -e "$one" ]] && left="$left $one"
    done
    if [[ -n "$left" ]]; then
        say "Still here, because they receive and rotate the logs other things may use too:"
        for one in $left; do say "  $one"; done
        warn "They name the $SERVICE_USER group: remove them (and restart rsyslog) BEFORE"
        warn "deleting the account, or log rotation fails for everything they cover."
    fi
    say "To remove the rest:  rm -rf $STATE_DIR $CONFIG_DIR; userdel $SERVICE_USER; groupdel $WEB_GROUP"
    exit 0
fi

# ---------------------------------------------------------------------------
# Replacing the program and nothing else
# ---------------------------------------------------------------------------
# Which package manager this machine has, worked out before anything uses it:
# an upgrade installs drivers too, and an upgrade never reaches the section
# below that used to work this out. Nothing is installed here.
#
# Read in a subshell rather than sourced. /etc/os-release sets VERSION, and
# this script has a VERSION of its own - sourcing it here would have this
# installer announce that it is upgrading isemon to "24.04.4 LTS".
OS_PRETTY="$( . /etc/os-release 2>/dev/null; printf '%s' "${PRETTY_NAME:-}" )"
case "$( . /etc/os-release 2>/dev/null; printf '%s%s' "${ID:-}" "${ID_LIKE:-}" )" in
    *rhel*|*fedora*|*centos*|*almalinux*) PKG="dnf";;
    *debian*|*ubuntu*) PKG="apt";;
    *) PKG="";;
esac

# The drivers for the two database servers. Neither is needed to run: this
# keeps everything in one file on this machine unless somebody says
# otherwise, and that file is part of Python. They are put here so that the
# choice is there on the page rather than being a thing somebody discovers
# they cannot make. Each is tried from the distribution first and from pip
# only if there is no package - and if neither works, that engine simply
# says so on the page instead of being offered.
db_driver() {                 # db_driver <words> <import> <package> <pip name>
    if python3 -c "import $2" 2>/dev/null; then
        good "$1: the driver is already here"
        return 0
    fi
    if [[ -n "$DRY_RUN" ]]; then
        say "would install $3 (or $4 with pip, if there is no package)"
        return 0
    fi
    if [[ "$PKG" == "dnf" ]]; then
        dnf install -y "$3" >/dev/null 2>&1 || true
    elif [[ "$PKG" == "apt" ]]; then
        # Debian names its Python packages in small letters (python3-pymysql).
        apt-get install -y "${3,,}" >/dev/null 2>&1 || true
    fi
    if ! python3 -c "import $2" 2>/dev/null; then
        pip3 install --break-system-packages "$4" >/dev/null 2>&1 \
            || pip3 install "$4" >/dev/null 2>&1 || true
    fi
    if python3 -c "import $2" 2>/dev/null; then
        good "$1: the driver is in place"
    else
        warn "$1: no driver could be installed; that engine will say so on the page"
        note "  the page offers it all the same, and says what is missing"
    fi
}

db_client() {                 # db_client <words> <program> <rpm> <deb>
    # The engine's own client, which is what the nightly dump is made with.
    # Not having it is not a failure: the nightly one falls back to a
    # portable copy, which needs nothing at all. So this says what it did and
    # carries on either way.
    if command -v "$2" >/dev/null 2>&1; then
        good "$1: $2 is already here, so the nightly dump will be its own"
        return 0
    fi
    if [[ -n "$DRY_RUN" ]]; then
        say "would install $3, which brings $2"
        return 0
    fi
    if [[ "$PKG" == "dnf" ]]; then
        dnf install -y "$3" >/dev/null 2>&1 || true
    elif [[ "$PKG" == "apt" ]]; then
        apt-get install -y "$4" >/dev/null 2>&1 || true
    fi
    if command -v "$2" >/dev/null 2>&1; then
        good "$1: $2 is in place, so the nightly dump will be its own"
    else
        warn "$1: $2 could not be installed"
        note "  the nightly copy still happens - as a portable copy rather than a dump,"
        note "  which is bigger but goes back into any engine. To have dumps: $PKG install $3"
    fi
}

# The one directory outside its own state that the daemon writes: which
# database everything is kept in cannot be saved in the database it is the
# address of, so those seven settings live in config.json and the dashboard
# has to be able to change them. Setgid, so a file the daemon replaces keeps
# the group; the file itself stays 0640, readable by root and by the daemon
# and by nobody else, because it holds a database password.
config_dir_writable() {
    not_a_link "$CONFIG_DIR" "$CONFIG_FILE"
    run install -d -m 2770 -o root -g "$SERVICE_USER" "$CONFIG_DIR"
    if [[ -f "$CONFIG_FILE" && ! -L "$CONFIG_FILE" && -z "$DRY_RUN" ]]; then
        chgrp -h "$SERVICE_USER" "$CONFIG_FILE" 2>/dev/null || true
        chmod 0640 "$CONFIG_FILE" 2>/dev/null || true
    fi
    command -v restorecon >/dev/null && run restorecon -R "$CONFIG_DIR" 2>/dev/null || true
}

# Asked for by --with-db, and done on a fresh install and on an upgrade
# alike. An option that is accepted and then quietly not carried out is
# worse than one that is refused.
# Since 1.10.173 Settings -> The database tunes the database server for its
# machine, and some of PostgreSQL's settings - shared_buffers, the one that
# matters most - take effect only when it is next started. The service
# account may restart a PostgreSQL on this machine and nothing else (a polkit
# rule, see deploy/49-isemon-database.rules), and the file beside its config
# tells the daemon so: polkit's own folder is closed to it.
POLKIT_RULE="/etc/polkit-1/rules.d/49-isemon-database.rules"
RESTART_MARK="$CONFIG_DIR/may-restart-database"
db_restart_rule() {
    if [[ -z "$DB_RESTART" ]]; then
        if [[ -e "$POLKIT_RULE" || -e "$RESTART_MARK" ]]; then
            step "Restarting PostgreSQL from the dashboard"
            run rm -f "$POLKIT_RULE" "$RESTART_MARK"
            good "taken away (--no-db-restart): the dashboard shows the command instead"
        fi
        return 0
    fi
    # Only where PostgreSQL is installed here as a service; a server
    # elsewhere is restarted by whoever looks after it.
    # (Into a variable rather than piped to grep -q: under pipefail a grep
    # that stops reading early can make the pipeline fail.)
    local units
    units="$(systemctl list-unit-files --no-legend --no-pager 'postgresql*' 2>/dev/null || true)"
    [[ -n "$units" ]] || return 0
    step "Restarting PostgreSQL from the dashboard"
    # polkit is what lets the account restart it; a minimal machine may not
    # have it (1.10.201: installed then, rather than the button going quiet).
    if [[ ! -d "${POLKIT_RULE%/*}" && ( -z "$DO_UPGRADE" || -n "$DO_DB_RIGHTS" ) ]]; then
        if [[ "$PKG" == "dnf" ]]; then
            run dnf install -y polkit >/dev/null 2>&1 || true
        elif [[ "$PKG" == "apt" ]]; then
            run apt-get install -y polkitd >/dev/null 2>&1 || true
        fi
        [[ -n "$DRY_RUN" ]] && run install -d -m 0755 "${POLKIT_RULE%/*}"
    fi
    if [[ ! -d "${POLKIT_RULE%/*}" ]]; then
        note "polkit is not installed, so the dashboard shows the command to restart"
        note "  PostgreSQL with rather than doing it"
        return 0
    fi
    sed -e "s/subject.user === \"isemon\"/subject.user === \"$SERVICE_USER\"/" \
        "$SOURCE_DIR/deploy/49-isemon-database.rules" | write_file "$POLKIT_RULE" 0644
    run install -m 0640 -o root -g "$SERVICE_USER" /dev/null "$RESTART_MARK"
    good "$SERVICE_USER may restart PostgreSQL, and nothing else ($POLKIT_RULE);"
    good "  install.sh --no-db-restart takes that away"
}

# ---------------------------------------------------------------------------
# Receiving the logs (1.10.201: on every install and every upgrade, unless
# --no-syslog). Each piece is added only where nothing of the machine's own
# is there already, and what is there is never replaced: a machine that
# already receives its logs its own way keeps doing exactly that.
# ---------------------------------------------------------------------------
REMOTE_DIR="/var/log/remote"
RSYSLOG_UMASK_DROPIN="/etc/systemd/system/rsyslog.service.d/isemon-umask.conf"
RSYSLOG_MAIN="/etc/rsyslog.conf"
RSYSLOG_DIR="/etc/rsyslog.d"
LOGROTATE_MAIN="/etc/logrotate.conf"
LOGROTATE_DIR="/etc/logrotate.d"

# Every file that already says how rsyslog listens, one per line.
rsyslog_listening_files() {
    local f
    for f in "$RSYSLOG_MAIN" "$RSYSLOG_DIR"/*.conf; do
        [[ -f "$f" && "$f" != "$RSYSLOG_FILE" ]] || continue
        grep -qE '^[[:space:]]*(input\(|module\(load="im(udp|tcp|relp|ptcp)"|\$(UDPServerRun|InputTCPServerRun|InputRELPServerRun|InputPTCPServerRun))' "$f" \
            && echo "$f"
    done
    return 0
}

# Every logrotate file other than ours that names /var/log/remote.
remote_rotated_elsewhere() {
    local f
    for f in "$LOGROTATE_MAIN" "$LOGROTATE_DIR"/*; do
        [[ -f "$f" && "$f" != "$REMOTE_LOGROTATE_FILE" ]] || continue
        grep -qE '^[^#]*/var/log/remote' "$f" && echo "$f"
    done
    return 0
}

receiving_packages() {
    # rsyslog itself, and the two modules a receiver over RELP and TLS needs
    # (docs/freeradius-rsyslog-forwarding.md): installed where missing,
    # nothing else touched.
    local want=() one
    if [[ "$PKG" == "dnf" ]]; then
        for one in rsyslog rsyslog-relp rsyslog-openssl; do
            rpm -q "$one" >/dev/null 2>&1 || want+=("$one")
        done
        ((${#want[@]})) || { good "rsyslog, rsyslog-relp and rsyslog-openssl are here"; return 0; }
        say "installing: ${want[*]}"
        run dnf install -y "${want[@]}" >/dev/null 2>&1 || warn "dnf could not install ${want[*]}"
    elif [[ "$PKG" == "apt" ]]; then
        for one in rsyslog rsyslog-relp rsyslog-openssl; do
            dpkg -s "$one" >/dev/null 2>&1 || want+=("$one")
        done
        ((${#want[@]})) || { good "rsyslog, rsyslog-relp and rsyslog-openssl are here"; return 0; }
        say "installing: ${want[*]}"
        run apt-get install -y "${want[@]}" >/dev/null 2>&1 || warn "apt could not install ${want[*]}"
    else
        warn "no package manager known here: install rsyslog, rsyslog-relp and rsyslog-openssl by hand"
    fi
}

# The service's own umask is applied on top of every mode rsyslog is told:
# RHEL ships UMask=0066, which turns 0640 into 0600. Loosened to 0027 only
# where it takes the group's read away; a stricter one that still lets the
# group read is left as it is.
receiving_umask() {
    local now
    now="$(systemctl show rsyslog -p UMask --value 2>/dev/null || true)"
    if [[ -z "$now" ]]; then
        note "the umask of rsyslog could not be read; nothing was changed"
        return 0
    fi
    if (( (8#${now} & 8#040) == 0 )); then
        good "rsyslog's umask is $now, which lets the $SERVICE_USER group read what it writes"
        return 0
    fi
    write_file "$RSYSLOG_UMASK_DROPIN" 0644 <<EOF
# Written by isemon's install.sh ($VERSION). rsyslog's own unit says
# UMask=$now, which takes the group's read away from every file it makes, so
# the daemon could not read the logs that arrive. Remove this file (and run
# systemctl daemon-reload) to go back to it.
[Service]
UMask=0027
EOF
    run systemctl daemon-reload
    good "rsyslog's umask was $now and is now 0027 ($RSYSLOG_UMASK_DROPIN)"
    RECV_RESTART="yes"
}

# /var/log/remote and everything already in it: readable by the daemon,
# added to and never taken away from. The folder's group becomes the
# daemon's only where it was root's; the files keep their owners and modes
# and get an ACL, which setfacl makes effective by widening the mask.
receiving_folder() {
    if [[ -L "$REMOTE_DIR" ]]; then
        warn "$REMOTE_DIR is a symbolic link; it was left alone"
        return 0
    fi
    if [[ ! -d "$REMOTE_DIR" ]]; then
        run install -d -m 0750 -o root -g "$SERVICE_USER" "$REMOTE_DIR"
        # Its SELinux label, on the folder made here only: one already there
        # keeps whatever somebody gave it.
        command -v restorecon >/dev/null && run restorecon "$REMOTE_DIR" 2>/dev/null || true
        good "$REMOTE_DIR made, 0750 root:$SERVICE_USER"
    else
        if [[ "$(stat -c %G "$REMOTE_DIR")" == "root" ]]; then
            run chgrp "$SERVICE_USER" "$REMOTE_DIR"
        fi
        run chmod g+rx "$REMOTE_DIR"
        good "$REMOTE_DIR: group $(stat -c %G "$REMOTE_DIR" 2>/dev/null), the group may read it"
    fi
    if command -v setfacl >/dev/null; then
        run setfacl -R -m "u:$SERVICE_USER:rX" "$REMOTE_DIR" 2>/dev/null || true
        if [[ -z "$DRY_RUN" ]]; then
            find "$REMOTE_DIR" -type d -exec setfacl -d -m "u:$SERVICE_USER:rX" {} + 2>/dev/null || true
        fi
        good "everything under $REMOTE_DIR is readable by $SERVICE_USER (an ACL; nothing else changed)"
    else
        warn "setfacl is not here: files already under $REMOTE_DIR keep their modes"
    fi
    return 0
}

setup_receiving() {       # setup_receiving fresh|upgrade
    local how="$1" added_files=()
    RECV_RESTART=""
    step "Receiving the logs"
    if systemctl is-active --quiet syslog-ng 2>/dev/null; then
        warn "syslog-ng is what receives the logs here, so rsyslog was not set up."
        note "  Give its files to the $SERVICE_USER group - in its destination:"
        note "    file(\"$REMOTE_DIR/\${HOST}/\${PROGRAM}.log\" create-dirs(yes)"
        note "         owner(root) group($SERVICE_USER) perm(0640) dir-group($SERVICE_USER) dir-perm(0750));"
        note "  and see docs/log-rotation-and-permissions.md for the rotation."
        receiving_folder
        return 0
    fi
    receiving_packages
    if [[ -z "$DRY_RUN" ]] && ! command -v rsyslogd >/dev/null; then
        warn "rsyslog is not installed, so nothing more was done here"
        receiving_folder
        return 0
    fi
    receiving_umask

    # What every file and folder rsyslog makes from now on looks like. The
    # 00 matters: rsyslog applies these to actions defined after them.
    if [[ -f "$RSYSLOG_PERMS_FILE" ]]; then
        good "$RSYSLOG_PERMS_FILE is already there and was left alone"
    else
        install_substituted "$SOURCE_DIR/deploy/rsyslog-permissions.conf" "$RSYSLOG_PERMS_FILE" 0644
        added_files+=("$RSYSLOG_PERMS_FILE")
        good "new logs and folders will be readable by $SERVICE_USER ($RSYSLOG_PERMS_FILE)"
        RECV_RESTART="yes"
    fi

    # The receiver: only where rsyslog does not listen already. Two inputs
    # on one port and rsyslog refuses its configuration.
    local listening
    listening="$(rsyslog_listening_files | tr '\n' ' ')"
    if [[ -f "$RSYSLOG_FILE" ]]; then
        good "$RSYSLOG_FILE is already there and was left alone"
    elif [[ -n "$listening" ]]; then
        good "rsyslog already listens for logs here ($listening), so no receiver was added"
        note "  the ISE part of it, to compare with: deploy/rsyslog-ise.conf"
    else
        local taken=""
        if command -v ss >/dev/null; then
            taken="$(ss -Hlnup 'sport = :514' 2>/dev/null | grep -v rsyslogd || true)"
            taken="$taken$(ss -Hlntp 'sport = :514' 2>/dev/null | grep -v rsyslogd || true)"
        fi
        if [[ -n "$taken" ]]; then
            warn "something other than rsyslog already listens on 514, so no receiver was added:"
            printf '%s\n' "$taken" | head -3 | sed 's/^/      /'
        else
            sed -e "s/dirGroup=\"isemon\"/dirGroup=\"$SERVICE_USER\"/" \
                -e "s/fileGroup=\"isemon\"/fileGroup=\"$SERVICE_USER\"/" \
                "$SOURCE_DIR/deploy/rsyslog-ise.conf" | write_file "$RSYSLOG_FILE" 0644
            added_files+=("$RSYSLOG_FILE")
            good "rsyslog will write the ISE logs into $REMOTE_DIR/<node>/ ($RSYSLOG_FILE)"
            RECV_RESTART="yes"
            RECV_LISTENER="yes"
        fi
    fi

    # Checked before rsyslog is restarted: a configuration it will not read
    # is a machine that stops writing every log it keeps. What this run
    # added is taken out again, so the machine is as it was.
    if [[ -z "$DRY_RUN" && -n "$RECV_RESTART" ]]; then
        if ! rsyslogd -N1 >/dev/null 2>&1; then
            warn "rsyslog does not accept its configuration with these, so they were taken out again:"
            rsyslogd -N1 2>&1 | grep -iE 'error|warn' | head -5 | sed 's/^/      /' || true
            local one
            for one in "${added_files[@]}"; do rm -f "$one"; note "    removed $one"; done
            RECV_LISTENER=""
        else
            systemctl enable rsyslog >/dev/null 2>&1 || true
            systemctl restart rsyslog 2>/dev/null || warn "rsyslog would not restart"
            good "rsyslog restarted with it"
        fi
    fi

    receiving_folder

    # Rotating what arrives - unless something of the machine's own does
    # already: logrotate refuses two stanzas for one file, and then rotates
    # neither.
    local rotated ours=""
    rotated="$(remote_rotated_elsewhere | tr '\n' ' ')"
    if [[ -f "$REMOTE_LOGROTATE_FILE" ]]; then
        good "$REMOTE_LOGROTATE_FILE is already there and was left alone"
        if ! grep -qE "^[[:space:]]*create[[:space:]]+[0-7]+[[:space:]]+[^[:space:]]+[[:space:]]+$SERVICE_USER\b" "$REMOTE_LOGROTATE_FILE"; then
            warn "  its \"create\" does not name the $SERVICE_USER group: the next rotation makes a file"
            warn "  this daemon cannot read. It should say:  create 0640 root $SERVICE_USER"
        fi
    elif [[ -n "$rotated" ]]; then
        good "$REMOTE_DIR is rotated already ($rotated), so no rotation was added"
        grep -hE '^[[:space:]]*create' $rotated 2>/dev/null | grep -qv "$SERVICE_USER" \
            && warn "  its \"create\" should name the $SERVICE_USER group:  create 0640 root $SERVICE_USER"
    else
        install_substituted "$SOURCE_DIR/deploy/remote-logs.logrotate" "$REMOTE_LOGROTATE_FILE" 0644
        if [[ -z "$DRY_RUN" ]] && command -v logrotate >/dev/null \
                && ! logrotate -d "$REMOTE_LOGROTATE_FILE" >/dev/null 2>&1; then
            warn "logrotate does not accept $REMOTE_LOGROTATE_FILE, so it was taken out again:"
            logrotate -d "$REMOTE_LOGROTATE_FILE" 2>&1 | grep -i error | head -3 | sed 's/^/      /' || true
            rm -f "$REMOTE_LOGROTATE_FILE"
        else
            good "what arrives rotates daily, thirty kept, readable by $SERVICE_USER ($REMOTE_LOGROTATE_FILE)"
            ours="yes"
        fi
    fi
    # The two things logrotate cannot do: the accounting files, which are
    # named for the day, and copies left behind by a change of naming. Only
    # with the rotation put in here: it deletes what is older than thirty
    # days, and a machine that rotates its own way may keep a year.
    if [[ -f "$TIDY_CRON_FILE" ]]; then
        good "$TIDY_CRON_FILE is already there and was left alone"
    elif [[ -n "$ours" ]]; then
        install_substituted "$SOURCE_DIR/deploy/isemon-logs-tidy" "$TIDY_CRON_FILE" 0755
        good "old eduroam accounting files are aged out daily ($TIDY_CRON_FILE)"
    fi

    # The port, to the senders named - and on a fresh install with none
    # named, to anybody, said loudly. An upgrade never opens it to anybody.
    if [[ -n "${RECV_LISTENER:-}" ]] && command -v firewall-cmd >/dev/null \
            && systemctl is-active --quiet firewalld; then
        if [[ -n "$LOG_FROM" ]]; then
            local senders fam proto
            IFS=',' read -r -a senders <<< "$LOG_FROM"
            for one in "${senders[@]}"; do
                one="$(echo "$one" | xargs)"
                [[ -z "$one" ]] && continue
                fam=ipv4; [[ "$one" == *:* ]] && fam=ipv6
                for proto in udp tcp; do
                    run firewall-cmd --permanent --add-rich-rule="rule family=$fam source address=$one port port=514 protocol=$proto accept" >/dev/null 2>&1 || true
                done
            done
            run firewall-cmd --reload >/dev/null 2>&1 || true
            say "opened 514/udp and 514/tcp to the senders given: $LOG_FROM"
        elif [[ "$how" == "fresh" ]]; then
            run firewall-cmd --permanent --add-port=514/udp >/dev/null 2>&1 || true
            run firewall-cmd --permanent --add-port=514/tcp >/dev/null 2>&1 || true
            run firewall-cmd --reload >/dev/null 2>&1 || true
            say "opened 514/udp and 514/tcp"
            warn "...to ANYBODY who can reach this machine. Whoever can send a line to"
            warn "514 can write an ISE refusal and so make a ban. Name the senders:"
            note "  ./install.sh --upgrade --log-from ISE1,ISE2  (or, by hand:"
            note "  firewall-cmd --permanent --remove-port=514/udp --remove-port=514/tcp"
            note "  firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=ISE1 port port=514 protocol=udp accept')"
        else
            note "514 was not opened in the firewall: name who sends with --log-from ISE1,ISE2, or by hand:"
            note "  firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=ISE1 port port=514 protocol=udp accept'"
        fi
    fi
}

# ---------------------------------------------------------------------------
# The database server's settings (1.10.201). Settings -> The database tunes
# PostgreSQL for its machine, and needed an administrator's password typed
# in every time. On a PostgreSQL on this machine the installer, as root, can
# give this program's own account the right to change THOSE settings and no
# others (PostgreSQL 15 and newer: GRANT ALTER SYSTEM ON PARAMETER) - signed
# in as postgres over its own socket, with no password asked, kept or
# written anywhere.
# ---------------------------------------------------------------------------
db_tune_rights() {
    local said engine host user names version dbname
    said="$(python3 - "$CONFIG_FILE" "$SOURCE_DIR/isemon.py" <<'PY' 2>/dev/null || true
import ast, json, sys
try:
    cfg = json.load(open(sys.argv[1]))
except Exception:
    cfg = {}
names = []
try:
    tree = ast.parse(open(sys.argv[2], encoding='utf-8').read())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(getattr(t, 'id', '') == 'TUNE_PG_NAMES'
                                                for t in node.targets):
            names = list(ast.literal_eval(node.value))
except Exception:
    pass
print('%s\t%s\t%s\t%s\t%s' % (str(cfg.get('db_engine') or 'sqlite').lower(),
                              str(cfg.get('db_host') or '') or '-',
                              str(cfg.get('db_user') or 'isemon'),
                              str(cfg.get('db_name') or 'isemon'), ' '.join(names)))
PY
)"
    IFS=$'\t' read -r engine host user dbname names <<< "$said"
    [[ "$host" == "-" ]] && host=""
    case "$engine" in
        postgres|postgresql|pgsql) ;;
        *) return 0;;
    esac
    step "Tuning PostgreSQL from the dashboard"
    case "$host" in
        ""|localhost|127.*|::1|"[::1]"|localhost.localdomain|/*) ;;
        *) if [[ "$host" != "$(hostname -s 2>/dev/null)" && "$host" != "$(hostname -f 2>/dev/null)" ]]; then
               note "the server is $host, not this machine: its administrator gives the rights there."
               note "  On it, as postgres:  GRANT ALTER SYSTEM ON PARAMETER shared_buffers, ... TO $user;"
               note "  (the list and the rest: docs/postgresql-tuning.md)"
               return 0
           fi;;
    esac
    if [[ -z "$names" || ! "$user" =~ ^[A-Za-z_][A-Za-z0-9_]*$ \
          || ! "$dbname" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
        warn "the settings or the account could not be read; nothing was given"
        return 0
    fi
    if ! id postgres >/dev/null 2>&1 || ! command -v psql >/dev/null; then
        note "PostgreSQL is not installed on this machine as postgres/psql; nothing was given"
        return 0
    fi
    pg_as() { (cd / && runuser -u postgres -- psql -X -A -t -q -v ON_ERROR_STOP=1 -d postgres "$@"); }
    if [[ -n "$DRY_RUN" ]]; then
        say "would give $user the right to change: $names"
        return 0
    fi
    version="$(pg_as -c 'SHOW server_version_num' 2>/dev/null | tr -dc 0-9)"
    if [[ -z "$version" ]]; then
        warn "postgres could not sign in over this machine's socket, so nothing was given."
        note "  Settings -> The database still asks for an administrator, as before."
        return 0
    fi
    if (( version < 150000 )); then
        note "PostgreSQL $((version / 10000)) cannot give the right to change a setting on its own"
        note "  (that came in 15): the dashboard asks for an administrator each time, as before."
        return 0
    fi
    if [[ "$(pg_as -c "SELECT 1 FROM pg_roles WHERE rolname = '$user'" 2>/dev/null)" != "1" ]]; then
        note "there is no account $user on this PostgreSQL yet; run this again once there is:"
        note "  sudo ./install.sh --db-rights"
        return 0
    fi
    local sql="" one
    for one in $names; do
        [[ "$one" =~ ^[a-z_]+$ ]] || continue
        sql+="GRANT ALTER SYSTEM ON PARAMETER $one TO \"$user\";"$'\n'
    done
    sql+="GRANT pg_read_all_settings TO \"$user\";"$'\n'
    # A function's rights are its database's: given in the one this program
    # uses, not in `postgres`.
    local fn_sql="GRANT EXECUTE ON FUNCTION pg_reload_conf() TO \"$user\";"
    if printf '%s' "$sql" | pg_as >/dev/null 2>&1 \
            && printf '%s\n' "$fn_sql" | (cd / && runuser -u postgres -- psql -X -A -t -q \
                   -v ON_ERROR_STOP=1 -d "$dbname") >/dev/null 2>&1; then
        good "$user may change the settings the dashboard tunes, and no others,"
        good "  and reload the server: Settings -> The database needs no administrator now"
    else
        warn "PostgreSQL refused to give the rights:"
        printf '%s' "$sql" | pg_as 2>&1 | head -3 | sed 's/^/      /' || true
    fi
}

install_db_drivers() {
    case "${WITH_DB:-}" in
        "")        return 0;;
        mariadb|mysql)
            step "The MariaDB driver"
            db_driver "MariaDB" pymysql python3-PyMySQL PyMySQL
            db_client "MariaDB" mariadb-dump mariadb default-mysql-client;;
        postgres|postgresql|pgsql)
            step "The PostgreSQL driver"
            db_driver "PostgreSQL" psycopg2 python3-psycopg2 psycopg2-binary
            db_client "PostgreSQL" pg_dump postgresql postgresql-client;;
        both|all)
            step "The database drivers"
            db_driver "MariaDB" pymysql python3-PyMySQL PyMySQL
            db_driver "PostgreSQL" psycopg2 python3-psycopg2 psycopg2-binary
            db_client "MariaDB" mariadb-dump mariadb default-mysql-client
            db_client "PostgreSQL" pg_dump postgresql postgresql-client;;
        *)         fail "--with-db takes mariadb, postgres or both - not ${WITH_DB}";;
    esac
    note "nothing has been configured and nothing has moved: this only puts the"
    note "driver in place, so that Settings -> The database has something to"
    note "talk to a server with. See docs/the-database.md."
}

if [[ -n "$DO_DB_RIGHTS" && -z "$DO_UPGRADE" ]]; then
    id "$SERVICE_USER" >/dev/null 2>&1 || fail "there is no $SERVICE_USER account here: install isemon first"
    install_db_drivers
    db_restart_rule
    db_tune_rights
    exit 0
fi

if [[ -n "$DO_UPGRADE" ]]; then
    step "Upgrading isemon to $VERSION"
    # One upgrade at a time: one from the pages is running already, unless
    # this is it (1.10.222).
    if [[ -z "${ISEMON_UPGRADE_FROM_PAGES:-}" ]] && systemctl is-active --quiet isemon-upgrade.service 2>/dev/null; then
        fail "an upgrade from the pages is running (isemon-upgrade.service); wait for it, then run this again"
    fi
    [[ -d "$LIB_DIR" ]] || fail "$LIB_DIR does not exist — this looks like a first install, so run it without --upgrade"
    # What isemon uses and this machine lacks, put in first (1.10.236).
    progress 1 "the packages isemon uses"
    ensure_packages upgrade
    # The PHP of the pages, to the release with the php2shell fix (1.10.250).
    if [[ -f "$WEB_DIR/index.php" ]]; then
        progress 1 "PHP"
        php_update
    fi
    # The Python isemon runs on, the newest that fits (1.10.252).
    progress 1 "Python"
    python_pick "$(config_engine)"
    progress 1 "copying the program"
    [[ -d "$LIB_DIR" ]] || fail "$LIB_DIR does not exist — this looks like a first install, so run it without --upgrade"
    was="$(python3 "$LIB_DIR/isemon.py" --version 2>/dev/null || echo unknown)"
    say "from $was"
    # Kept beside it, so an upgrade that does not take can be undone in one
    # line rather than by finding the old tarball again. Under the version it
    # IS, and never over one already kept: running the upgrade a second time
    # after it failed used to copy the failing version over the good copy.
    was_word="$(printf '%s' "$was" | tr -cd 'A-Za-z0-9._-' | sed 's/^isemon//')"
    BAK="$LIB_DIR/isemon.py.${was_word:-previous}"
    if [[ -z "$DRY_RUN" && ! -e "$BAK" ]]; then
        cp -p "$LIB_DIR/isemon.py" "$BAK" 2>/dev/null || true
        [[ -d "$WEB_DIR" ]] && cp -a "$WEB_DIR" "$LIB_DIR/web.${was_word:-previous}" 2>/dev/null || true
    fi
    [[ -n "$DRY_RUN" ]] || cp -f "$LIB_DIR/isemon.py" "$LIB_DIR/isemon.py.bak" 2>/dev/null || true
    run install -D -m 0755 "$SOURCE_DIR/isemon.py" "$LIB_DIR/isemon.py"
    for extra in INSTALL.md README.md; do
        [[ -f "$SOURCE_DIR/$extra" ]] && run install -D -m 0644 "$SOURCE_DIR/$extra" "$LIB_DIR/$extra"
    done
    if [[ -d "$SOURCE_DIR/docs" ]]; then
        run rm -rf "$LIB_DIR/docs"
        run cp -r "$SOURCE_DIR/docs" "$LIB_DIR/docs"
    fi
    if [[ -d "$SOURCE_DIR/test" ]]; then
        run rm -rf "$LIB_DIR/test"
        run cp -r "$SOURCE_DIR/test" "$LIB_DIR/test"
    fi
    progress 2 "the dashboard's files"
    if [[ -n "$WITH_WEB" && -d "$WEB_DIR" ]]; then
        run install -D -m 0644 "$SOURCE_DIR/web/index.php" "$WEB_DIR/index.php"
        run install -D -m 0644 "$SOURCE_DIR/web/isemon-api.php" "$WEB_DIR/isemon-api.php"
        run install -D -m 0644 "$SOURCE_DIR/web/banfeed.php" "$WEB_DIR/banfeed.php"
        # The health check (1.10.222): what monitoring and a balancer ask.
        run install -D -m 0644 "$SOURCE_DIR/web/healthz.php" "$WEB_DIR/healthz.php"
        # The answer to an ACME CA on port 80 (1.10.251): asked only once
        # Settings - Automatic certificates is switched on.
        run install -D -m 0644 "$SOURCE_DIR/web/acme.php" "$WEB_DIR/acme.php"
        # What PHP will accept on this page. Without it, putting a copy of
        # the database back is refused by PHP's own two-megabyte default
        # before it reaches anything that could explain why.
        run install -D -m 0644 "$SOURCE_DIR/web/.user.ini" "$WEB_DIR/.user.ini"
        run install -D -m 0644 "$SOURCE_DIR/web/favicon.svg" "$WEB_DIR/favicon.svg"
        run rm -rf "$WEB_DIR/flags"
        run cp -r "$SOURCE_DIR/web/flags" "$WEB_DIR/flags"
        # The languages of the page. Ours are put there afresh; a file
        # somebody added of their own (de.json, say) is left where it is.
        if [[ -d "$SOURCE_DIR/web/lang" ]]; then
            run install -d -m 0755 "$WEB_DIR/lang"
            run cp -f "$SOURCE_DIR"/web/lang/*.json "$WEB_DIR/lang/"
        fi
        run chown -R root:root "$WEB_DIR"
        run find "$WEB_DIR" -type d -exec chmod 0755 {} +
        run find "$WEB_DIR" -type f -exec chmod 0644 {} +
        command -v restorecon >/dev/null && run restorecon -R "$WEB_DIR" 2>/dev/null || true
    fi
    # Before the restart, so the daemon comes back able to do it.
    #
    # 1.10.0 gave the dashboard the database settings but left this machine's
    # /etc/isemon as it was - root-owned and closed to the daemon by the
    # unit's own ProtectSystem - so saving them failed with a read-only file
    # system. An upgrade puts that right rather than leaving somebody to
    # find it.
    progress 3 "where the database settings are written"
    step "Where the database settings are written"
    config_dir_writable
    good "$CONFIG_DIR is writable by $SERVICE_USER (2770), $CONFIG_FILE stays 0640"

    # Added in 1.10.11, so an installation upgraded from before it has no
    # such folder and the first night would be the one to find that out.
    not_a_link "$STATE_DIR" "$STATE_DIR/dumps"
    run install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$STATE_DIR/dumps"

    # The router's key, which 1.10.97 moved out of /run (emptied at every
    # restart, and so at this one). Carried across now, before the restart
    # empties it, so the router is not met as a stranger.
    if [[ -f /run/isemon/known_hosts && ! -e "$STATE_DIR/known_hosts" ]]; then
        run install -m 0600 -o "$SERVICE_USER" -g "$SERVICE_USER" \
            /run/isemon/known_hosts "$STATE_DIR/known_hosts"
    fi

    # What earlier installs did not do, or did only half: the web accounts in
    # a group for the token alone (see web_group_setup), and SELinux letting
    # them reach the daemon at all.
    if [[ -n "$WITH_WEB" && -d "$WEB_DIR" ]]; then
        progress 4 "the web server's accounts"
        step "The web server's accounts"
        web_group_setup
        if command -v getenforce >/dev/null && [[ "$(getenforce)" != "Disabled" ]]; then
            run setsebool -P httpd_can_network_connect 1 2>/dev/null || \
                warn "could not set httpd_can_network_connect"
        fi
        # A php-fpm that is already running has the groups it started with.
        if [[ -z "$DRY_RUN" ]]; then
            for unit in $(php_fpm_units); do
                systemctl restart "$unit" || warn "$unit would not restart"
            done
        fi
        # The vhost is the site's own and is never replaced; the one this
        # version ships is put beside the program for comparing.
        run install -D -m 0644 "$SOURCE_DIR/deploy/nginx-isemon.conf" "$LIB_DIR/nginx-isemon.conf"
        # Since 1.10.105 the file refuses a direct request itself (404), so a
        # vhost from before the line below is not a hole - and a yellow line
        # on every upgrade of a site whose vhost is its own and is never
        # touched here was a warning nobody could make go away from here.
        # Said once, quietly, with the line to add.
        nginx_php2shell_guard
        php2shell_said
        if [[ -f "$NGINX_CONF" ]] && ! grep -q 'isemon-api' "$NGINX_CONF"; then
            note "$NGINX_CONF has no rule of its own for /isemon-api.php; the file"
            note "  answers a direct request with 404 itself. For nginx to refuse it first,"
            note "  add:  location = /isemon-api.php { return 404; }"
            note "  (as in $LIB_DIR/nginx-isemon.conf)"
        fi
        # The ban feed is a page of its own. A vhost that hands only index.php
        # to PHP would give a firewall asking for it a 404 - or the file itself.
        if [[ -f "$NGINX_CONF" ]] && ! grep -q 'banfeed' "$NGINX_CONF" \
                && ! grep -qE 'location[[:space:]]+~[[:space:]]+.*\\\.php' "$NGINX_CONF"; then
            warn "$NGINX_CONF hands no page but index.php to PHP, so the ban feed"
            warn "  (/banfeed.php) cannot be fetched; see the \\.php block in"
            warn "  $LIB_DIR/nginx-isemon.conf"
        fi
    fi

    # Before the restart, so the daemon comes back with whatever it now has.
    progress 5 "the database drivers"
    install_db_drivers
    db_restart_rule
    # Only where asked for by name (1.10.202): a plain upgrade leaves both
    # as they are on a machine where they already work.
    if [[ -n "$DO_DB_RIGHTS" ]]; then
        db_tune_rights
    fi
    if [[ -n "$SYSLOG_ASKED" && -n "$WITH_SYSLOG" ]]; then
        setup_receiving upgrade
    fi

    # The unit and the rotation may have changed between versions; the config
    # file and the database never are.
    progress 6 "the units, and what the pages may ask of root"
    python_link
    run install -D -m 0644 "$SOURCE_DIR/deploy/isemon.service" "$UNIT_FILE"
    run install -D -m 0644 "$SOURCE_DIR/deploy/isemon.logrotate" "$LOGROTATE_FILE"
    root_helpers
    chrony_check upgrade
    install_console upgrade
    run systemctl daemon-reload
    progress 7 "restarting isemon"
    run systemctl restart isemon.service
    if [[ -n "$DRY_RUN" ]]; then
        good "--dry-run: nothing was changed, and nothing was restarted"
        exit 0
    fi
    sleep 2
    # Give it a moment longer than the first look: a database with a year of
    # records in it takes a second or two to be brought up to date, and a
    # restart that is still doing that is not a restart that has failed.
    for _ in 1 2 3 4 5; do
        systemctl is-active --quiet isemon.service && break
        sleep 1
    done
    systemctl is-active --quiet isemon.service || python_back || true
    if systemctl is-active --quiet isemon.service; then
        progress 8 "checking it answers"
        good "isemon $VERSION is running."
        if [[ -n "$WITH_WEB" && -d "$WEB_DIR" ]]; then
            sleep 2
            web_group_tighten
        fi
        run "$BIN_LINK" --check || true
    else
        # Saying "look at the journal" is asking somebody to go and find what
        # this already knows. Show it.
        warn "it did not come back up. This is what it said:"
        echo
        journalctl -u isemon.service -n 25 --no-pager -o cat 2>/dev/null | sed 's/^/    /' || true
        echo
        say "The old version is kept as $BAK if you need it back:"
        say "  install -m 0755 $BAK $LIB_DIR/isemon.py && systemctl restart isemon"
        say "(and its page as $LIB_DIR/web.${was_word:-previous}, to copy back to $WEB_DIR)"
        fail "the upgrade did not take"
    fi
    exit 0
fi

# ---------------------------------------------------------------------------
# A fresh install
# ---------------------------------------------------------------------------
step "isemon $VERSION"
say "A banning daemon for Cisco ISE: it reads the two nodes' syslog, works out"
say "who is trying to break into the VPN, and carries that to a Mikrotik."
[[ -n "$DRY_RUN" ]] && warn "--dry-run: nothing will actually be changed."

# ---- what is already here --------------------------------------------------
# PKG itself was worked out further up, before the upgrade path, because an
# upgrade needs it too and never gets this far.
step "Looking at this machine"
say "${OS_PRETTY:-unknown}"
[[ -n "$PKG" ]] || warn "I do not recognise this distribution; no packages will be installed."

python3 --version >/dev/null 2>&1 || fail "python3 is not installed"
say "$(python3 --version)"
python3 - <<'PY' || fail "this Python is too old; isemon needs 3.8 or newer"
import sys
sys.exit(0 if sys.version_info >= (3, 8) else 1)
PY

# ---- packages --------------------------------------------------------------
step "Packages"
need=()
# The ssh client is openssh-clients on the RHEL family and openssh-client on
# Debian; asked for by the wrong name, apt refused the whole list.
ssh_pkg="openssh-clients"
[[ "$PKG" == "apt" ]] && ssh_pkg="openssh-client"
command -v ssh        >/dev/null || need+=("$ssh_pkg")
command -v ssh-keygen >/dev/null || need+=("$ssh_pkg")
command -v setfacl    >/dev/null || need+=("acl")
if [[ -n "$WITH_WEB" ]]; then
    command -v nginx >/dev/null || need+=("nginx")
    command -v php-fpm >/dev/null || php-fpm -v >/dev/null 2>&1 || need+=("php-fpm" "php-cli")
fi
# python3 is the standard library and nothing else, on purpose: there is no
# pip install anywhere in this.
if ((${#need[@]})); then
    say "missing: ${need[*]}"
    if [[ "$PKG" == "dnf" ]]; then
        run dnf install -y "${need[@]}"
    elif [[ "$PKG" == "apt" ]]; then
        run apt-get update && run apt-get install -y "${need[@]}"
    else
        fail "install these by hand and run this again: ${need[*]}"
    fi
else
    good "everything needed is already here"
fi

install_db_drivers

# What else isemon uses (ssh, openssl, smbclient, chrony, colorama...): put in
# when it is missing, never insisted on - see ensure_packages.
ensure_packages fresh
[[ -n "$WITH_WEB" ]] && php_update

# ---- the account it runs as ------------------------------------------------
step "The service account"
if id "$SERVICE_USER" >/dev/null 2>&1; then
    good "$SERVICE_USER already exists"
else
    run useradd --system --home-dir "$STATE_DIR" --shell /sbin/nologin \
        --comment "isemon daemon" "$SERVICE_USER"
    good "made $SERVICE_USER"
fi
# Whoever the web server runs as has to be able to read the API token in
# /run/isemon. They are put in a group of their own for it (web_group_setup),
# and php-fpm is asked what it runs as - on AlmaLinux that is `apache`, not
# the `nginx` the web server itself runs as.
if [[ -n "$WITH_WEB" ]]; then
    web_group_setup
    note "A group added to a running process does not reach it: php-fpm and"
    note "nginx are restarted further down, which is what makes it take."
fi
added="$WEB_USERS"

# ---- asking -----------------------------------------------------------------
if [[ -z "$ASSUME_YES" ]]; then
    step "A few questions"
    note "Enter to keep what is in brackets."
    ask ISE_PATHS "Where the ISE logs land, comma separated"
    ask WATCH_DEVICES "Which NetworkDeviceName may earn a ban"
    note "Anything here is NEVER banned, whatever it does. Your own offices and"
    note "your own VPN concentrators belong here. It can be changed later."
    ask NEVER_BLOCK "Never ban (comma separated, may be empty)"
    ask MIKROTIK_HOST "The Mikrotik's address (empty = none for now)"
    if [[ -n "$MIKROTIK_HOST" ]]; then
        ask MIKROTIK_USER "The account on it"
        ask MIKROTIK_LIST "The address list it may touch"
    fi
    if [[ -n "$WITH_WEB" ]]; then
        ask SERVER_NAME "The dashboard's hostname"
        ask ALLOW_FROM "Who may reach it (CIDRs, comma separated, empty = your RFC1918 networks)"
    fi
    ask ADMIN_USER "The first dashboard account"
    ask_secret ADMIN_PASSWORD "Its password (empty = make one and print it)"
fi

if [[ -n "$ALLOW_FROM" ]]; then
    cidr_list_ok "$ALLOW_FROM" || fail "--allow takes addresses and networks, comma separated"
fi
if [[ -n "$LOG_FROM" ]]; then
    cidr_list_ok "$LOG_FROM" || fail "--log-from takes addresses and networks, comma separated"
fi

# ---- the program itself -----------------------------------------------------
step "Installing the daemon"
run install -D -m 0755 "$SOURCE_DIR/isemon.py" "$LIB_DIR/isemon.py"
for extra in INSTALL.md README.md; do
    [[ -f "$SOURCE_DIR/$extra" ]] && run install -D -m 0644 "$SOURCE_DIR/$extra" "$LIB_DIR/$extra"
done
if [[ -d "$SOURCE_DIR/docs" ]]; then
    run rm -rf "$LIB_DIR/docs"
    run cp -r "$SOURCE_DIR/docs" "$LIB_DIR/docs"
fi
if [[ -d "$SOURCE_DIR/test" ]]; then
    run rm -rf "$LIB_DIR/test"
    run cp -r "$SOURCE_DIR/test" "$LIB_DIR/test"
fi
python_pick "${WITH_DB:-sqlite}"
python_link
good "$BIN_LINK"

not_a_link "$STATE_DIR" "$STATE_DIR/backups" "$STATE_DIR/dumps" "$LOG_DIR"
run install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$STATE_DIR"
run install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$STATE_DIR/backups"
# The nightly dump, which is the engine's own: pg_dump's, mariadb-dump's, or
# on the file SQLite's own backup. Kept apart from the copies because they go
# back into different places.
run install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$STATE_DIR/dumps"
run install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$LOG_DIR"
config_dir_writable
# ...after the account and its folder: the rule names the one, and the file
# that says the rule is there lives in the other.
db_restart_rule

# ---- the configuration ------------------------------------------------------
step "Configuration"
if [[ -f "$CONFIG_FILE" ]]; then
    good "$CONFIG_FILE is already there and was left alone"
else
    # Written by Python rather than by heredoc: it is JSON, and the values
    # come from answers that may hold quotes, commas and backslashes.
    if [[ -n "$DRY_RUN" ]]; then
        note "[would write] $CONFIG_FILE"
    else
        ISE_PATHS="$ISE_PATHS" WATCH_DEVICES="$WATCH_DEVICES" NEVER_BLOCK="$NEVER_BLOCK" \
        MIKROTIK_HOST="$MIKROTIK_HOST" MIKROTIK_USER="$MIKROTIK_USER" \
        MIKROTIK_LIST="$MIKROTIK_LIST" SERVER_NAME="$SERVER_NAME" \
        python3 - "$CONFIG_FILE" <<'PY'
import json, os, sys
out = {
    'ise_paths': [p.strip() for p in os.environ['ISE_PATHS'].split(',') if p.strip()],
    'watch_devices': os.environ['WATCH_DEVICES'].strip(),
    'site_name': os.environ['SERVER_NAME'].split('.')[0],
}
if os.environ.get('NEVER_BLOCK', '').strip():
    out['never_block'] = os.environ['NEVER_BLOCK'].strip()
if os.environ.get('MIKROTIK_HOST', '').strip():
    out['mikrotik_host'] = os.environ['MIKROTIK_HOST'].strip()
    out['mikrotik_user'] = os.environ['MIKROTIK_USER'].strip()
    out['mikrotik_list'] = os.environ['MIKROTIK_LIST'].strip()
    out['mikrotik_sync'] = 1
with open(sys.argv[1], 'w') as f:
    json.dump(out, f, indent=2, sort_keys=True)
    f.write('\n')
PY
        chmod 0640 "$CONFIG_FILE"
        chown root:"$SERVICE_USER" "$CONFIG_FILE"
    fi
    good "$CONFIG_FILE"
fi
note "  what you save on the dashboard goes into the database and wins over this file."
note "  The exception is which database that is - db_engine and the six beside it -"
note "  which is written here, because a database cannot hold the address of itself."
run install -D -m 0644 "$SOURCE_DIR/deploy/config.json" "$CONFIG_DIR/config.json.example"
# A configuration kept from before that already names a PostgreSQL here.
db_tune_rights

# ---- reading the ISE logs ---------------------------------------------------
step "Reading the ISE logs"
IFS=',' read -r -a paths <<< "$ISE_PATHS"
missing=0
for one in "${paths[@]}"; do
    one="$(echo "$one" | xargs)"
    [[ -z "$one" ]] && continue
    if [[ -d "$one" ]]; then
        # The files are written by root; the daemon must be able to read them
        # and must not be able to write them. An ACL says exactly that without
        # changing who owns them, which matters because rsyslog recreates them.
        if command -v setfacl >/dev/null; then
            run setfacl -R -m "u:$SERVICE_USER:rX" "$one" 2>/dev/null || true
            # rX rather than r (1.10.201): a folder made in it later was not
            # one the daemon could enter.
            run setfacl -R -d -m "u:$SERVICE_USER:rX" "$one" 2>/dev/null || true
            # ...and every folder above it has to be enterable, or the ACL on
            # the leaf is unreachable.
            up="$(dirname "$one")"
            while [[ "$up" != "/" && "$up" != "." ]]; do
                run setfacl -m "u:$SERVICE_USER:x" "$up" 2>/dev/null || true
                up="$(dirname "$up")"
            done
        fi
        good "$one — readable by $SERVICE_USER"
    else
        warn "$one does not exist yet"
        missing=$((missing + 1))
    fi
done
if (( missing )); then
    note "That is fine before the ISE nodes have sent anything: the daemon"
    note "waits for the files and starts reading the moment they appear."
    note "Point ISE at this machine under Administration -> System -> Logging"
    note "-> Remote Logging Targets, with Failed Attempts and Passed"
    note "Authentications sent to it."
fi
# Receiving the logs is done unless --no-syslog says otherwise (1.10.201):
# it used to need --with-syslog, so a machine installed without it had no
# rsyslog receiver, no permissions for what arrives and no rotation of it.
if [[ -n "$WITH_SYSLOG" ]]; then
    setup_receiving fresh
fi

# ---- the first account ------------------------------------------------------
# Made BEFORE the daemon first starts, as the daemon's own account (so the
# database it makes is the daemon's). Made after, it raced the daemon, which
# makes an `admin` of its own with a random password on its first start: the
# password given here was then thrown away, and the "does it exist" test - a
# substring search that `fulladmin` in every row always passed - said it had
# been left alone.
step "The first account"
if [[ -z "$DRY_RUN" ]]; then
    exists="$(runuser -u "$SERVICE_USER" -- "$BIN_LINK" --users --json 2>/dev/null \
              | python3 -c 'import json,sys
want = sys.argv[1].strip().lower()
try:
    rows = json.load(sys.stdin).get("users") or []
except ValueError:
    rows = []
print("yes" if any(str(r.get("name","")).lower() == want for r in rows) else "")' "$ADMIN_USER" \
              2>/dev/null || true)"
    if [[ -n "$exists" ]]; then
        if [[ -n "$ADMIN_PASSWORD" ]]; then
            if ISEMON_PASSWORD="$ADMIN_PASSWORD" runuser -u "$SERVICE_USER" -- \
                "$BIN_LINK" --passwd "$ADMIN_USER" >/dev/null; then
                good "$ADMIN_USER already existed; its password is now the one given here"
            else
                warn "the password of $ADMIN_USER could not be changed (at least 8 characters?)"
            fi
        else
            good "$ADMIN_USER already exists and was left alone"
            [[ -f "$STATE_DIR/first-login.txt" ]] && \
                note "  its first password is in $STATE_DIR/first-login.txt"
        fi
    else
        if [[ -z "$ADMIN_PASSWORD" ]]; then
            ADMIN_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_urlsafe(12))')"
            MADE_ONE="yes"
        fi
        # A password the program would refuse, said with its reason rather
        # than as "could not be made".
        if [[ ${#ADMIN_PASSWORD} -lt 8 ]]; then
            fail "--admin-password needs at least eight characters"
        fi
        # The password through the environment, not the command line, where
        # every account on the machine could read it in the process list.
        ISEMON_PASSWORD="$ADMIN_PASSWORD" runuser -u "$SERVICE_USER" -- \
            "$BIN_LINK" --add-user "$ADMIN_USER" --role fulladmin \
            --note "made by the installer" >/dev/null \
            || fail "the first account could not be made"
        good "$ADMIN_USER may sign in, as a full administrator"
        if [[ -n "${MADE_ONE:-}" ]]; then
            printf '\n    %sname:     %s%s\n' "$C_OK" "$ADMIN_USER" "$C_OFF"
            printf '    %spassword: %s%s\n\n' "$C_OK" "$ADMIN_PASSWORD" "$C_OFF"
            warn "Write that down now — it is not shown again."
            note "Change it with:  isemon --passwd $ADMIN_USER"
        fi
    fi
fi

# ---- systemd ----------------------------------------------------------------
step "The service"
run install -D -m 0644 "$SOURCE_DIR/deploy/isemon.service" "$UNIT_FILE"
run install -D -m 0644 "$SOURCE_DIR/deploy/isemon.logrotate" "$LOGROTATE_FILE"
root_helpers
chrony_check fresh
install_console fresh
run systemctl daemon-reload
run systemctl enable isemon.service >/dev/null
run systemctl restart isemon.service
sleep 2
if [[ -z "$DRY_RUN" ]]; then
    systemctl is-active --quiet isemon.service || python_back || true
    if systemctl is-active --quiet isemon.service; then
        good "isemon.service is running"
    else
        warn "it did not start — the last of its log:"
        journalctl -u isemon -n 20 --no-pager || true
        fail "sort that out and run this again"
    fi
fi

# ---- the dashboard ----------------------------------------------------------
if [[ -n "$WITH_WEB" ]]; then
    step "The dashboard"
    run install -d -m 0755 "$WEB_DIR"
    run install -D -m 0644 "$SOURCE_DIR/web/index.php" "$WEB_DIR/index.php"
    run install -D -m 0644 "$SOURCE_DIR/web/isemon-api.php" "$WEB_DIR/isemon-api.php"
    run install -D -m 0644 "$SOURCE_DIR/web/banfeed.php" "$WEB_DIR/banfeed.php"
    run install -D -m 0644 "$SOURCE_DIR/web/healthz.php" "$WEB_DIR/healthz.php"
    run install -D -m 0644 "$SOURCE_DIR/web/acme.php" "$WEB_DIR/acme.php"
    run install -D -m 0644 "$SOURCE_DIR/web/.user.ini" "$WEB_DIR/.user.ini"
    run install -D -m 0644 "$SOURCE_DIR/web/favicon.svg" "$WEB_DIR/favicon.svg"
    run rm -rf "$WEB_DIR/flags"
    run cp -r "$SOURCE_DIR/web/flags" "$WEB_DIR/flags"
    if [[ -d "$SOURCE_DIR/web/lang" ]]; then
        run install -d -m 0755 "$WEB_DIR/lang"
        run cp -f "$SOURCE_DIR"/web/lang/*.json "$WEB_DIR/lang/"
    fi
    run chown -R root:root "$WEB_DIR"
    run find "$WEB_DIR" -type d -exec chmod 0755 {} +
    run find "$WEB_DIR" -type f -exec chmod 0644 {} +
    good "$WEB_DIR"

    # ---- certificates --------------------------------------------------
    run install -d -m 0755 "$CERT_DIR"
    if [[ -n "$CERT_FILE" && -n "$KEY_FILE" ]]; then
        run install -m 0644 "$CERT_FILE" "$CERT_DIR/isemon.pem"
        run install -m 0600 "$KEY_FILE" "$CERT_DIR/isemon.key"
        good "your certificate is in $CERT_DIR"
    elif [[ -f "$CERT_DIR/isemon.pem" && -f "$CERT_DIR/isemon.key" ]]; then
        good "$CERT_DIR/isemon.pem is already there"
    else
        warn "no certificate given — making one this machine signs itself"
        note "Browsers will complain about it. Replace the two files in"
        note "$CERT_DIR with a real pair and reload nginx."
        run openssl req -x509 -nodes -newkey rsa:2048 -days 825 \
            -keyout "$CERT_DIR/isemon.key" -out "$CERT_DIR/isemon.pem" \
            -subj "/CN=$SERVER_NAME" \
            -addext "subjectAltName=DNS:$SERVER_NAME" 2>/dev/null
        run chmod 0600 "$CERT_DIR/isemon.key"
    fi

    # ---- nginx ---------------------------------------------------------
    if [[ -z "$ALLOW_FROM" ]]; then
        allow_lines=$'    allow 192.168.0.0/16;\n    allow 172.16.0.0/12;\n    allow 10.0.0.0/8;'
    else
        allow_lines=""
        IFS=',' read -r -a cidrs <<< "$ALLOW_FROM"
        for one in "${cidrs[@]}"; do
            one="$(echo "$one" | xargs)"
            [[ -z "$one" ]] && continue
            allow_lines+="    allow $one;"$'\n'
        done
        allow_lines="${allow_lines%$'\n'}"
    fi
    if [[ -f "$NGINX_CONF" ]]; then
        warn "$NGINX_CONF already exists and was left alone"
        note "The one this version ships is at $LIB_DIR/nginx-isemon.conf for comparing."
        run install -D -m 0644 "$SOURCE_DIR/deploy/nginx-isemon.conf" "$LIB_DIR/nginx-isemon.conf"
        nginx_php2shell_guard
    else
        # sed rather than a heredoc: the shipped file is the documented one,
        # and only the hostname and the allow rules differ per machine.
        if [[ -n "$DRY_RUN" ]]; then
            note "[would write] $NGINX_CONF for $SERVER_NAME"
        else
            # Where php-fpm listens: /run/php-fpm/www.sock on the RHEL family,
            # /run/php/php8.x-fpm.sock on Debian and Ubuntu.
            php_sock=""
            if [[ ! -S /run/php-fpm/www.sock ]]; then
                for one in /run/php/php*-fpm.sock; do
                    [[ -S "$one" ]] && { php_sock="$one"; break; }
                done
            fi
            python3 - "$SOURCE_DIR/deploy/nginx-isemon.conf" "$NGINX_CONF" \
                     "$SERVER_NAME" "$allow_lines" "$php_sock" <<'PY'
import re, sys
src, dst, host, allows, sock = sys.argv[1:6]
text = open(src).read()
text = text.replace('blacklistmt.example.loc', host)
if sock:
    text = text.replace('unix:/run/php-fpm/www.sock;', 'unix:%s;' % sock)
# Replace the three default allow lines, wherever they are, with whatever was
# asked for - and only those three, so the localhost lines stay.
# (With whatever comment is written after each: the shipped file has one on
# the first line, and a pattern that did not allow for it matched nothing -
# so --allow was quietly ignored and the page stayed open to every private
# network there is.)
text, n = re.subn(r'(?m)^    allow 192\.168\.0\.0/16;[^\n]*\n    allow 172\.16\.0\.0/12;[^\n]*\n'
                  r'    allow 10\.0\.0\.0/8;[^\n]*$', lambda m: allows, text)
if n != 1:
    sys.stderr.write('the allow lines in %s were not where they were expected; '
                     'nothing was written\n' % src)
    sys.exit(1)
open(dst, 'w').write(text)
PY
        fi
        good "$NGINX_CONF for $SERVER_NAME"
    fi

    # ---- SELinux -------------------------------------------------------
    if command -v getenforce >/dev/null && [[ "$(getenforce)" != "Disabled" ]]; then
        step "SELinux"
        say "it is $(getenforce)"
        # nginx and php-fpm have to reach the daemon on localhost, and PHP has
        # to read the token in /run/isemon.
        run setsebool -P httpd_can_network_connect 1 2>/dev/null || \
            warn "could not set httpd_can_network_connect"
        command -v restorecon >/dev/null && run restorecon -R "$WEB_DIR" 2>/dev/null || true
        good "nginx may talk to the daemon"
        note "If the dashboard says the token is unreadable, look in"
        note "/var/log/audit/audit.log and run:  ausearch -m avc -ts recent | audit2allow -M isemon"
    fi

    # ---- firewall ------------------------------------------------------
    if command -v firewall-cmd >/dev/null && systemctl is-active --quiet firewalld; then
        run firewall-cmd --permanent --add-service=https >/dev/null 2>&1 || true
        run firewall-cmd --permanent --add-service=http  >/dev/null 2>&1 || true
        run firewall-cmd --reload >/dev/null 2>&1 || true
        good "80 and 443 are open"
    fi

    # ---- start them ----------------------------------------------------
    if [[ -z "$DRY_RUN" ]]; then
        # Asked of each unit by name: `list-unit-files | grep -q` under
        # pipefail failed whenever grep stopped reading early, and then the
        # unit was skipped - php-fpm never restarted into its new group.
        # nginx is checked BEFORE it is restarted: a restart into a
        # configuration it will not read takes every site on it down.
        nginx_ok="yes"
        if command -v nginx >/dev/null && ! nginx -t >/dev/null 2>&1; then
            nginx_ok=""
            warn "nginx is not happy with its configuration, so it was NOT restarted — nginx -t says:"
            nginx -t || true
        fi
        for unit in $(php_fpm_units) nginx; do
            systemctl cat "$unit.service" >/dev/null 2>&1 || continue
            [[ "$unit" == nginx && -z "$nginx_ok" ]] && continue
            systemctl enable "$unit" >/dev/null 2>&1 || true
            systemctl restart "$unit" || warn "$unit would not start"
        done
        [[ -n "$nginx_ok" ]] && good "nginx is happy with its configuration"
    fi
fi

# ---- does it work -----------------------------------------------------------
step "Checking"
if [[ -z "$DRY_RUN" ]]; then
    sleep 1
    "$BIN_LINK" --check || true
    if [[ -n "$WITH_WEB" ]]; then
        # The one failure that looks like something else entirely: the daemon
        # is fine, the page says it is not answering, and the real trouble is
        # a file the web server may not read.
        web_group_tighten
        token_ok=""
        for web_user in $added; do
            if runuser -u "$web_user" -- test -r /run/isemon/api-token 2>/dev/null; then
                token_ok="$web_user"
                break
            fi
        done
        if [[ -n "$token_ok" ]]; then
            good "  $token_ok can read the API token, so the dashboard can reach the daemon"
        else
            warn "  no web account can read /run/isemon/api-token yet"
            note "  The dashboard will say the daemon is not answering until it can."
            note "  Usually: php-fpm runs as a user that is not in the $WEB_GROUP group."
            note "    grep '^user' /etc/php-fpm.d/www.conf"
            note "    usermod -a -G $WEB_GROUP <that user>; systemctl restart php-fpm isemon"
            note "  If that is already right, it is SELinux:"
            note "    ausearch -m avc -ts recent | audit2allow -M isemon-local"
            note "    semodule -i isemon-local.pp"
        fi
    fi
fi

step "Done"
if [[ -n "$WITH_WEB" ]]; then
    say "The dashboard:  https://$SERVER_NAME/"
fi
say "From the shell:"
say "  isemon --status          what it is doing"
say "  isemon --blocked         who is banned"
say "  isemon --failed          the failed attempts"
say "  isemon --whitelist       what may never be banned"
say "  isemon --users           who may open the dashboard"
say "  isemon --console         all of it by its menus (root sees it at login)"
say "  isemon --help            everything else"
echo
if [[ -z "$MIKROTIK_HOST" ]]; then
    note "No router was given, so bans are recorded here and enforced nowhere."
    note "Add one under Settings -> Reaching the router, make a key there, put"
    note "its public half on the Mikrotik, and point a drop rule at the list."
else
    note "Next: Settings -> Reaching the router -> Make a key, put its public"
    note "half on $MIKROTIK_HOST, and add a rule there:"
    note "  /ip firewall filter add chain=input src-address-list=$MIKROTIK_LIST action=drop"
fi
note "And put your own networks on the whitelist before anything else:"
note "  isemon --allow 192.168.0.0/16 --why \"the office\""
