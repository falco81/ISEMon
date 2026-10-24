#!/bin/bash
#
# otp-radius-setup.sh - everything in otp-radius-detail.md, done.
#
# This is section 6.2 of that document as a file you run instead of a block
# you paste. It sets up, on the TOKEN SERVER:
#
#   1. the FreeRADIUS detail, reply and one-line accounting logs
#   2. an id of its own for every request, so the two logs can be joined
#      exactly rather than by name and clock
#   3. the rlm_perl handler passing that id on, and putting the token
#      server's own reason for a refusal into the RADIUS reply
#   4. the token CGI writing that id on its own log lines
#   5. the script and the cron entry that ship the records to syslog
#
# It does the work and nothing else: no test sign-ins, no tcpdump, no
# proving the path. Those are in sections 2, 4 and 6.1 of the document and
# they are worth doing - they are simply not what a script should decide to
# do on somebody's live server.
#
# Everything it touches is copied first. A patch that is already in is said
# out loud and left alone, so it is safe on a server that is half-way there
# and safe to run twice. Anything else that goes wrong stops it.
#
# NOTHING HERE IS EVER JUDGED. These logs are read so that a token attempt
# can be shown with the address, the machine and the tunnel group that
# caused it. No address in them is ever blocked and nothing in them counts
# towards a ban.
#
#   ./otp-radius-setup.sh --collector 192.0.2.10
#   ./otp-radius-setup.sh --from /root/install --collector isemon.example.int
#
# Options:
#   --from DIR        where the six files are (default: this script's folder,
#                     or /root/install if they are not beside it)
#   --collector HOST  where the records are forwarded: the isemon machine,
#                     by address or by name. Without it this asks, because
#                     there is no sensible guess and nothing here is built
#                     in. Run with it to answer in advance.
#   --yes             do not ask before writing (the list and the copy are
#                     still made, and still shown)
#   --skip-sums       do not check the files against the sums below
#   --no-restart      change everything, restart nothing (see the end)
#   --help
#
set -e
set -u

FROM=""
COLLECTOR=""
SUMS=yes
RESTART=yes
ASSUME_YES=no
# Where this was started from. Taken before anything else, because the work
# below moves around and the copy of everything belongs where whoever ran
# this can find it.
STARTED_IN=$(pwd)

while [ $# -gt 0 ]; do
	case "$1" in
		--from)       FROM="${2:-}"; shift 2 ;;
		--collector)  COLLECTOR="${2:-}"; shift 2 ;;
		--yes|-y)     ASSUME_YES=yes; shift ;;
		--skip-sums)  SUMS=no; shift ;;
		--no-restart) RESTART=no; shift ;;
		--help|-h)    sed -n '2,50p' "$0"; exit 0 ;;
		*) echo "not a thing this takes: $1 (try --help)" >&2; exit 2 ;;
	esac
done

say()  { echo "   $*"; }
step() { echo; echo "== $*"; }
die()  { echo; echo "stopped: $*" >&2; exit 1; }

[ "$(id -u)" = "0" ] || die "this has to run as root: it writes in /etc/raddb and /var/www."

# Where the records are to be forwarded. There is nothing to guess from and
# nothing is built in: on one site it is an address on a management network,
# on another a name in a domain, and the only thing that knows is whoever is
# running this. So it is asked for, once, before any of the work starts -
# not half way through, when six things have already been changed.
#
# The asking is done on the terminal where there is one, so that this still
# works when the script itself is being fed down a pipe; and off standard
# input where there is not, so that an answer can be piped in. With neither
# there is nobody to ask, and it says so rather than guessing.
askline() {
	if [ -r /dev/tty ] && [ -t 1 ]; then
		read -r REPLY < /dev/tty || return 1
	else
		read -r REPLY || return 1
	fi
}

ask_collector() {
	if ! { { [ -r /dev/tty ] && [ -t 1 ]; } || [ ! -t 0 ]; }; then
		die "no --collector was given and there is nobody to ask. Run it again
         with the answer in it, for example:

             $0 --collector 192.0.2.10"
	fi
	echo
	echo "Where should the RADIUS records be forwarded to?"
	echo "That is the isemon machine, by address or by name - it is what goes"
	echo "into the rsyslog rule, and nothing here has a default for it."
	while [ -z "$COLLECTOR" ]; do
		printf "  isemon machine: "
		askline || die "nothing was answered, so nothing was changed."
		COLLECTOR=$(echo "$REPLY" | tr -d '[:space:]')
		case "$COLLECTOR" in
			''|COLLECTOR)
				COLLECTOR=""
				echo "  - an address or a name, please." ;;
			*[!A-Za-z0-9.:_-]*)
				echo "  - $COLLECTOR is not an address or a name."
				COLLECTOR="" ;;
		esac
	done
	echo
	printf "Forwarding to %s over UDP 514. Right? [y/N] " "$COLLECTOR"
	askline || REPLY=""
	case "$REPLY" in
		y|Y|yes|YES) : ;;
		*) COLLECTOR=""; ask_collector ;;
	esac
}
[ -n "$COLLECTOR" ] || ask_collector

# Where the files are. Beside this script is the usual case - the whole
# folder is copied to the server and this is run out of it - and
# /root/install is what the document tells people to use.
if [ -z "$FROM" ]; then
	HERE=$(cd "$(dirname "$0")" && pwd)
	if [ -f "$HERE/raddb-accounting-logging.patch" ]; then
		FROM="$HERE"
	else
		FROM="/root/install"
	fi
fi
[ -d "$FROM" ] || die "$FROM is not a folder. Say where the files are with --from."

NEEDED="raddb-accounting-logging.patch totpcgi-handler-reason.patch
        totpcgi-index-rid.patch radacct-syslog-ship.py radacct-ship-cron
        31-forward-radacct.conf"
for one in $NEEDED; do
	[ -s "$FROM/$one" ] || die "$FROM/$one is missing or empty. All six have to be there."
done

# The sums of the six as they shipped. A file that arrived damaged - a paste
# that joined two lines, an scp that stopped half way - is worth catching
# here rather than as a server that will not start afterwards.
if [ "$SUMS" = "yes" ]; then
	step "checking the six files against the sums they shipped with"
	WRONG=""
	while read -r want name; do
		[ -n "$name" ] || continue
		got=$(md5sum "$FROM/$name" | awk '{print $1}')
		if [ "$got" != "$want" ]; then
			WRONG="$WRONG $name"
			echo "   $name: shipped $want, here $got" >&2
		fi
	done <<-'TABLE'
		8b810af4b6b406ae1d8efcacce58d89f raddb-accounting-logging.patch
		617ca6e536a16c1c47fc32e964a199e3 radacct-syslog-ship.py
		8d2e551e39d341f6ed7e27cbb2dfbf1e radacct-ship-cron
		2e2367181ea173b3511d97b797b34ead 31-forward-radacct.conf
		fe54e7fe45da0d76efe772730daa9a2c totpcgi-handler-reason.patch
		02a4de08e939893828f1e7bbcbc5bb26 totpcgi-index-rid.patch
	TABLE
	[ -z "$WRONG" ] || die "these did not arrive as they left:$WRONG. Copy them again."
	say "all six are as they shipped"
fi

# `patch` itself. A minimal CentOS 6 does not have it, and without it the
# first patch below would stop this half way through instead of here, before
# anything has been touched. yum on a CentOS 6 no longer finds anything with
# the repositories it was installed with - they moved to vault.centos.org -
# which is what centos6-yum/ beside this script is for (the guide, §1).
if ! command -v patch >/dev/null 2>&1; then
	die "patch is not installed. yum install patch - and if yum cannot find it,
     unpack centos6-yum/centos6-yum-repos.tgz first (otp-radius-detail.md, §1)."
fi

# Applying a patch that is already in is not a failure. Anything else is.
#    apply <-pN> <patch file> [the one file to patch]
apply() {
	strip=$1; pf=$2; tgt=${3:-}
	if patch $strip -R -f --dry-run $tgt -i "$pf" >/dev/null 2>&1; then
		say "already applied, left alone: $(basename "$pf")"
	else
		patch $strip -N $tgt -i "$pf"
	fi
}

STAMP=$(date +%F)

# --------------------------------------------------------------------------
# Everything that is about to be touched, said out loud and kept, BEFORE the
# first change is made.
#
# The raddb files are not a list written down here: they are read out of the
# patches themselves, so that what is shown is what will really be written
# on whatever server this is, and a patch that grows a file later cannot
# leave this saying something out of date.
# --------------------------------------------------------------------------
files_in_patch() {   # <patch file> <the folder its paths are relative to> <strip>
	sed -n 's/^+++ \([^\t ]*\).*/\1/p' "$1" | while read -r one; do
		[ "$3" = "1" ] && one=${one#*/}
		one=${one#./}
		echo "$2/$one"
	done
}

TOUCHES=$(
	files_in_patch "$FROM/raddb-accounting-logging.patch" /etc/raddb 1
	files_in_patch "$FROM/totpcgi-handler-reason.patch"   /etc/raddb 0
	[ -f /var/www/totpcgi/index.cgi ] && files_in_patch \
		"$FROM/totpcgi-index-rid.patch" /var/www/totpcgi 0
	echo /etc/raddb/dictionary
	echo /etc/raddb/sites-enabled/default
	echo /etc/rsyslog.conf
	echo /etc/rsyslog.d/31-forward-radacct.conf
	echo /usr/local/sbin/radacct-syslog-ship.py
	echo /etc/cron.d/radacct-ship
)
TOUCHES=$(echo "$TOUCHES" | sed '/^$/d' | sort -u)

step "what this is going to write, and nothing has been written yet"
HAVE=""
for one in $TOUCHES; do
	if [ -e "$one" ]; then
		echo "   change   $one"
		HAVE="$HAVE $one"
	else
		echo "   create   $one"
	fi
done
echo "   chown    /var/log/radius, /var/www/totpcgi/index.cgi"
echo "   write    /var/lib/radacct-ship/*.offset  (how far each log was read)"
echo "   restart  radiusd, rsyslog"

# ...and a copy of every one of those that exists, as one file, in the
# folder this was started from - not somewhere under /etc, where a mistake
# during the next ten minutes could take the copy with it.
KEEP="$STARTED_IN/otp-radius-backup-$(hostname -s 2>/dev/null || echo host)-$(date +%Y%m%d-%H%M%S).tar.gz"
step "keeping a copy of all of that first"
if [ -n "$HAVE" ]; then
	# Paths go in relative to /, so the tar can be unpacked with `tar -C /`
	# and every file lands exactly where it came from.
	# shellcheck disable=SC2086
	tar -czf "$KEEP" -C / $(for one in $HAVE; do echo "${one#/}"; done)
	say "$KEEP"
	say "$(tar -tzf "$KEEP" | wc -l) file(s) in it. Putting them all back is:"
	say "    tar -xzf $KEEP -C /"
else
	say "there is nothing here yet to keep a copy of"
fi

if [ "$ASSUME_YES" != "yes" ]; then
	echo
	printf "Go ahead and write all of that? [y/N] "
	if askline && case "$REPLY" in y|Y|yes|YES) true ;; *) false ;; esac; then
		:
	else
		echo
		echo "Nothing was changed. The copy above is still there; delete it if you"
		echo "do not want it."
		exit 0
	fi
fi

step "keeping a second copy, on the server, of the two whole trees"
if [ -d /etc/raddb.bak-$STAMP ]; then
	say "/etc/raddb.bak-$STAMP is already there, so it is left as it is"
else
	cp -a /etc/raddb /etc/raddb.bak-$STAMP
	say "/etc/raddb.bak-$STAMP"
fi
if [ -f /var/www/totpcgi/index.cgi ]; then
	[ -f /var/www/totpcgi/index.cgi.bak-$STAMP ] \
		|| cp -a /var/www/totpcgi/index.cgi /var/www/totpcgi/index.cgi.bak-$STAMP
	say "/var/www/totpcgi/index.cgi.bak-$STAMP"
fi

step "1. the detail and reply logs, and the one-line accounting log"
cd /etc/raddb
apply -p1 "$FROM/raddb-accounting-logging.patch"
if [ -d /var/log/radius ]; then
	chown -R radiusd:radiusd /var/log/radius
	say "/var/log/radius belongs to radiusd"
fi

step "2. an id of its own for every request"
if grep -q Totp-Request-Id /etc/raddb/dictionary; then
	say "the attribute is already in /etc/raddb/dictionary"
else
	printf '\nATTRIBUTE\tTotp-Request-Id\t\t3000\tstring\n' >> /etc/raddb/dictionary
	say "Totp-Request-Id added to /etc/raddb/dictionary"
fi
# It goes in as the FIRST thing inside authorize{}, because auth_log a few
# lines below writes the request to the detail log and an attribute set
# after that is not in what was written.
#
# The port is Packet-Src-Port, with no IP in it: that is the name in
# FreeRADIUS's own internal dictionary, where it sits beside
# Packet-Src-IP-Address under a name that does not match it. Asking for
# Packet-Src-IP-Port asks for an attribute that does not exist, and the
# server does not complain - it expands it to nothing, and the token log
# then reads rid=127.0.0.1: with nothing after the colon.
if grep -q Totp-Request-Id /etc/raddb/sites-enabled/default; then
	say "the request is already being given one in sites-enabled/default"
else
	perl -0pi -e 's/^authorize \{\n/authorize {\n\tupdate request {\n\t\tTotp-Request-Id := "%{Packet-Src-IP-Address}:%{Packet-Src-Port}"\n\t}\n\n/m' \
		/etc/raddb/sites-enabled/default
	grep -q Totp-Request-Id /etc/raddb/sites-enabled/default \
		|| die "nothing was written into sites-enabled/default - it has no plain
         'authorize {' line for this to go after. Put the update request
         block in by hand, as section 6.1 of the document shows."
	say "update request added at the top of authorize{}"
fi

step "3. passing it on, and the token server's reason into the reply"
cd /etc/raddb
apply -p0 "$FROM/totpcgi-handler-reason.patch"

step "4. writing it down on the token server's own log line"
# Through the inode, never over it. patch does not edit a file in place: it
# writes a new one and renames it over the old, so the file that ends up
# there belongs to whoever ran the command. Apache serves that CGI through
# suexec, which refuses to run a script it does not own - and that reaches
# whoever is signing in as a bare 500 with an empty body, with the file's
# contents perfectly fine.
if [ ! -f /var/www/totpcgi/index.cgi ]; then
	say "there is no /var/www/totpcgi/index.cgi here, so this step is skipped"
	say "(the id is still made and passed on; the token log will not carry it)"
else
	WORK=$(mktemp /tmp/index.cgi.work.XXXXXX)
	cp -a /var/www/totpcgi/index.cgi "$WORK"
	apply -p0 "$FROM/totpcgi-index-rid.patch" "$WORK"
	cat "$WORK" > /var/www/totpcgi/index.cgi
	rm -f "$WORK"
	chown totpcgi:totpcgi /var/www/totpcgi/index.cgi 2>/dev/null || true
	say "written back through the original file: $(ls -l /var/www/totpcgi/index.cgi | awk '{print $3":"$4}')"
fi

step "5. shipping the records to syslog"
install -m 700 "$FROM/radacct-syslog-ship.py" /usr/local/sbin/
mkdir -p /var/lib/radacct-ship
say "/usr/local/sbin/radacct-syslog-ship.py"
sed "s/COLLECTOR/$COLLECTOR/g" "$FROM/31-forward-radacct.conf" \
	> /etc/rsyslog.d/31-forward-radacct.conf
say "/etc/rsyslog.d/31-forward-radacct.conf, forwarding to $COLLECTOR"
grep -q COLLECTOR /etc/rsyslog.d/31-forward-radacct.conf \
	&& die "the word COLLECTOR is still in the rule that was just written, so
         nothing would be forwarded. Put $COLLECTOR into
         /etc/rsyslog.d/31-forward-radacct.conf by hand."
# rsyslog cuts at 2048 bytes by default and a detail record goes past it.
# This has to be before every ModLoad and every rule, so: the first line.
if [ -s /etc/rsyslog.conf ] && grep -q '^\$MaxMessageSize' /etc/rsyslog.conf; then
	say "the message size limit is already raised"
elif [ -s /etc/rsyslog.conf ]; then
	sed -i '1i $MaxMessageSize 8192' /etc/rsyslog.conf
	say "\$MaxMessageSize 8192 put at the top of /etc/rsyslog.conf"
else
	# An empty file is the one case sed's "insert before line 1" does
	# nothing at all on: there is no line 1 to insert before.
	echo '$MaxMessageSize 8192' > /etc/rsyslog.conf
	say "\$MaxMessageSize 8192 written into an empty /etc/rsyslog.conf"
fi
grep -q '^\$MaxMessageSize' /etc/rsyslog.conf \
	|| die "the message size limit is still not in /etc/rsyslog.conf, and a
         detail record longer than 2048 bytes would arrive cut in half. Put
         \$MaxMessageSize 8192 on its very first line by hand."


step "6. starting from now rather than from the whole history"
if [ -d /var/log/radius/radacct ]; then
	n=0
	for f in $(find /var/log/radius/radacct -type f -name '*detail-*' 2>/dev/null); do
		k=$(echo "${f#/}" | tr '/' '_')
		[ -f "/var/lib/radacct-ship/${k}.offset" ] && continue
		stat -c %s "$f" > "/var/lib/radacct-ship/${k}.offset"
		n=$((n + 1))
	done
	say "$n file(s) marked as read up to here; anything already marked was left"
fi
install -m 644 "$FROM/radacct-ship-cron" /etc/cron.d/radacct-ship
say "/etc/cron.d/radacct-ship - started once a minute, sweeping every 5s"

step "7. and only now, the restart"
if [ "$RESTART" = "no" ]; then
	echo
	echo "Everything is in place and nothing was restarted, as asked. None of it"
	echo "is doing anything until it is, and the configuration has NOT been"
	echo "checked yet. Before the restart:"
	echo
	echo "    radiusd -XC          # has to end: Configuration appears to be OK"
	echo "    service radiusd restart"
	echo "    service rsyslog restart"
	exit 0
fi
say "checking the configuration before anything is restarted"
radiusd -XC || die "radiusd -XC is not happy, so nothing was restarted and the
         server is still running on what it had. The whole of /etc/raddb as
         it was is in /etc/raddb.bak-$STAMP:

             rm -rf /etc/raddb && mv /etc/raddb.bak-$STAMP /etc/raddb"
service radiusd restart
service rsyslog restart

echo
echo "Done. What to look at, in this order:"
echo
echo "  1. a sign-in, and the token log line it makes:"
echo "         radtest USER TOKEN 127.0.0.1 1812 testing123"
echo "         tail -1 /var/log/messages"
echo "     it should carry rid=<address>:<port> with a port on the end of it."
echo "  2. the records leaving, and arriving at $COLLECTOR:"
echo "         /usr/local/sbin/radacct-syslog-ship.py -v"
echo "         tcpdump -ni any udp port 514 and host $COLLECTOR"
echo "  3. isemon, under Settings -> The OTP logs, with the RADIUS detail log"
echo "     switched on."
echo
echo "Going back: patch -R with the same files, or the copies taken at the"
echo "start - /etc/raddb.bak-$STAMP and index.cgi.bak-$STAMP."
