# The isemon console when root signs in (isemon 1.10.228), as otp does it.
# Installed as /etc/profile.d/zz-isemon-console.sh. Switched with
# `isemon --console-at-login on|off`; q in the console leaves it for this
# shell, and `isemon --console` opens it again. Nothing happens for a
# command run over SSH, scp/sftp, a non-interactive shell, a shell opened
# from the console itself, or when ISEMON_NO_CONSOLE is set. No choice file
# at all is off.
if [ -n "${PS1:-}" ] && [ -t 0 ] && [ -t 1 ] && [ -z "${ISEMON_CONSOLE:-}" ] \
   && [ -z "${ISEMON_NO_CONSOLE:-}" ] && [ -z "${SSH_ORIGINAL_COMMAND:-}" ] \
   && [ "$(id -u 2>/dev/null)" = "0" ] && [ -x /usr/local/bin/isemon ] \
   && [ -f /etc/isemon-console-login ] \
   && [ ! -L /etc/isemon-console-login ] \
   && [ "$(head -c 3 /etc/isemon-console-login 2>/dev/null)" = "on" ]; then
    export ISEMON_CONSOLE=1
    /usr/local/bin/isemon --console
fi
