#!/usr/bin/env bash
# Read-only audit script: strictly checks for active CVE-2026-109618 / php2shell exploit behavior
#
# Usage: sudo ./check_compromise.sh [--hours N] [--php X.Y]
#
#   --hours N   How far back the time-based checks look (default 24, or $WINDOW_HOURS).
#               When run from cron, keep it longer than the interval between runs,
#               or anything that happens in the gap goes unchecked.
#   --php X.Y   Only check this PHP-FPM version (default: every installed version).
#
# Tuning via environment: WEB_USERS, SITES_ROOT, ALLOWED_PORTS, ALLOW_CMD_REGEX.
# Exit codes: 0 nothing found, 1 indicators found, 2 could not run.
# Targets Ubuntu 22.04+ (systemd journal, iproute2 ss, procps, GNU find).

set -u

WINDOW_HOURS="${WINDOW_HOURS:-24}"
PHP_VER=""
WEB_USERS="${WEB_USERS:-www-data,forge}"
SITES_ROOT="${SITES_ROOT:-/home/forge}"
# Remote ports web users normally talk to: SSH, SMTP, web, MySQL, Postgres, Redis.
ALLOWED_PORTS="${ALLOWED_PORTS:-22 25 80 443 465 587 3306 5432 6379}"
# Known-good command lines for shells/interpreters run by web users or spawned by PHP-FPM:
# artisan and composer (scheduler cron, queue workers, deploys) and sendmail (mail()).
ALLOW_CMD_REGEX="${ALLOW_CMD_REGEX:-^(((/usr)?/bin/)?(ba)?sh -c )?(/usr/bin/)?php[0-9.]* ([^ ]*/)?(artisan|composer(\.phar)?) |^(((/usr)?/bin/)?(ba)?sh -c )?/usr/sbin/sendmail }"
# A command line containing any of these is never trusted, even if it matches the allowlist,
# so "bash -c '... /dev/tcp/...' # artisan" cannot hide behind it.
DENY_CMD_REGEX='/dev/(tcp|udp)/|\b(nc|ncat|netcat|socat|telnet|curl|wget|base64)\b|\$\(|`|\beval\b|artisan tinker'

REASONS=()

# shellcheck disable=SC2001 # indenting every line of multi-line details
flag() {
    REASONS+=("$1"$'\n'"$(sed 's/^/     /' <<<"${2%$'\n'}")")
}

is_allowed_cmd() {
    [[ -n $ALLOW_CMD_REGEX && $1 =~ $ALLOW_CMD_REGEX ]] && ! [[ $1 =~ $DENY_CMD_REGEX ]]
}

# 1. PHP-FPM segmentation faults (possible memory-corruption exploit attempts).
# The kernel logs "php-fpm8.3[1234]: segfault at ..."; the FPM master logs "exited on signal 11"
# to the journal or, on Ubuntu's default config, to /var/log/phpX.Y-fpm.log.
fpm_log_segfaults() {
    local line stamp
    # shellcheck disable=SC2086 # the * must glob over installed versions
    grep -hE 'signal 11|SIGSEGV' /var/log/php${PHP_VER:-*}-fpm.log /var/log/php${PHP_VER:-*}-fpm.log.1 2>/dev/null |
        while IFS= read -r line; do
            # "[21-Oct-2026 10:00:00] WARNING: ..." -> "21 Oct 2026 10:00:00", which GNU date parses
            stamp=${line:1:20}
            stamp=$(date -d "${stamp//-/ }" +%s 2>/dev/null) || continue
            ((stamp >= SINCE_EPOCH)) && printf '%s\n' "$line"
        done
}

check_segfaults() {
    local ver_re=${PHP_VER//./\\.} hits
    hits=$(
        journalctl _TRANSPORT=kernel --since "$SINCE" -g "php-fpm${ver_re:-[0-9.]*}\[[0-9]+\]: segfault" -q --no-pager 2>/dev/null
        journalctl -u "php${PHP_VER:-*}-fpm.service" --since "$SINCE" -g 'signal 11|SIGSEGV' -q --no-pager 2>/dev/null
        fpm_log_segfaults
    )
    [[ -n $hits ]] && flag "PHP-FPM segmentation fault(s) in the last $WINDOW_HOURS hours:" "$(tail -n 5 <<<"$hits")"
}

# 2. Shells or network tools run by web users without a terminal (typical reverse/bind shell).
# Matches on the real binary name (comm), so putting "artisan" in the arguments does not exempt it.
check_shells() {
    local pid user tty comm args hits=""
    while read -r pid user tty comm args; do
        [[ $tty == "?" ]] || continue
        [[ $comm =~ ^(bash|sh|dash|zsh|ksh|ash|php[0-9.]*|python[0-9.]*|perl|ruby|nc|ncat|netcat|socat|telnet)$ ]] || continue
        is_allowed_cmd "$args" && continue
        hits+="$pid $user $args"$'\n'
    done < <(ps -u "$WEB_USERS" -o pid=,user=,tty=,comm=,args= 2>/dev/null)
    [[ -n $hits ]] && flag "Shell or network tool running as $WEB_USERS without a terminal (expected briefly during a deploy):" "$hits"
}

# 3. Processes started by a PHP-FPM worker, which is how a web shell runs commands.
check_fpm_children() {
    local workers hits
    workers=$(ps -eo pid=,comm=,args= | awk -v c="^php-fpm${PHP_VER//./\\.}" \
        '$2 ~ c && $3 == "php-fpm:" && $4 == "pool" { printf "%s%s", sep, $1; sep = "," }')
    [[ -n $workers ]] || return
    hits=$(ps --ppid "$workers" -o pid=,user=,args= 2>/dev/null | while read -r pid user args; do
        is_allowed_cmd "$args" || printf '%s %s %s\n' "$pid" "$user" "$args"
    done)
    [[ -n $hits ]] && flag "PHP-FPM worker started a process:" "$hits"
}

# 4. Web-user processes running from temp dirs, from memory (fileless malware), or from a deleted file.
check_exe_paths() {
    local p exe hits=""
    for p in /proc/[0-9]*; do
        [[ " $WEB_UIDS " == *" $(stat -c %u "$p" 2>/dev/null) "* ]] || continue
        exe=$(readlink "$p/exe" 2>/dev/null) || continue
        case $exe in
            /tmp/* | /var/tmp/* | /dev/shm/* | /run/user/* | /memfd:*) ;;
            /usr/* | /opt/*) continue ;; # package upgrades leave running binaries "(deleted)"
            *" (deleted)") ;;
            *) continue ;;
        esac
        hits+="${p#/proc/} $exe: $(tr '\0' ' ' <"$p/cmdline" 2>/dev/null)"$'\n'
    done
    [[ -n $hits ]] && flag "Web-user process running from a temp dir, memory, or a deleted file:" "$hits"
}

# 5. Established TCP connections owned by web users to unusual remote ports.
# Matches on socket owner uid rather than process name, so a reverse shell named "sh" is caught too.
# Inbound connections to an allowed local port (nginx, SSH) and loopback peers are ignored.
# Gotcha: a reverse shell over port 443 still slips through; only a baseline of known hosts would catch it.
check_sockets() {
    local hits
    hits=$(ss -Htnpe state established 2>/dev/null | awk -v uids=" $WEB_UIDS " -v ports=" $ALLOWED_PORTS " '
        function port(a) { sub(/.*:/, "", a); return a }
        function host(a) { sub(/:[^:]*$/, "", a); gsub(/[][]/, "", a); sub(/^::ffff:/, "", a); return a }
        {
            uid = ""
            for (i = 5; i <= NF; i++) if ($i ~ /^uid:/) uid = substr($i, 5)
            if (uid == "" || index(uids, " " uid " ") == 0) next
            h = host($4)
            if (h ~ /^127\./ || h == "::1") next
            if (index(ports, " " port($4) " ") || index(ports, " " port($3) " ")) next
            print $3, "->", $4, $5
        }')
    [[ -n $hits ]] && flag "Web user holds a connection to an unusual remote port:" "$hits"
}

# 6. Executables, scripts or ELF binaries written to temp dirs within the window.
check_temp_files() {
    local f hits=""
    while IFS= read -r -d '' f; do
        if [[ -x $f || $f =~ \.(sh|so|php[0-9]?|phtml|phar|py|pl)$ || $(head -c4 "$f" 2>/dev/null) == $'\x7fELF' ]]; then
            hits+="$f"$'\n'
        fi
    done < <(find /tmp /var/tmp /dev/shm -maxdepth 3 -type f -mmin "-$WINDOW_MINUTES" -print0 2>/dev/null)
    [[ -n $hits ]] && flag "Executable or script written to /tmp, /var/tmp or /dev/shm in the last $WINDOW_HOURS hours:" "$hits"
}

# 7. Web shells in Laravel apps. A stock app has no PHP in public/ besides index.php, and none in
# storage/ besides compiled Blade views. Not time-bound: a planted shell stays a problem until removed.
check_webshells() {
    local app hits=""
    for app in "$SITES_ROOT"/*/ "$SITES_ROOT"/*/current/; do
        [[ -f ${app}artisan ]] || continue
        # Trailing slashes make find follow storage/, which zero-downtime deploys symlink.
        hits+=$(find "${app}public/" "${app}storage/" -regextype posix-extended -type f \
            -iregex '.*\.(php[0-9]?|phtml|phar)' ! -path "${app}public/index.php" \
            ! -path '*/framework/views/*' ! -path '*/vendor/*' 2>/dev/null)$'\n'
    done
    hits=$(sed '/^$/d' <<<"$hits")
    [[ -n $hits ]] && flag "Unexpected PHP file in a Laravel public/ or storage/ dir (possible web shell):" "$hits"
}

# 8. Persistence: SSH keys or crontabs changed within the window.
check_persistence() {
    local u homes=(/root) hits
    for u in ${WEB_USERS//,/ }; do
        homes+=("$(getent passwd "$u" | cut -d: -f6)")
    done
    hits=$(
        find "${homes[@]/%//.ssh}" -maxdepth 1 -type f -name 'authorized_keys*' -mmin "-$WINDOW_MINUTES" 2>/dev/null
        find /var/spool/cron /etc/cron.d /etc/crontab -maxdepth 2 -type f -mmin "-$WINDOW_MINUTES" 2>/dev/null
    )
    [[ -n $hits ]] && flag "SSH keys or crontab changed in the last $WINDOW_HOURS hours (fine if you did it):" "$hits"
}

usage() {
    sed -n '4,10p' "$0" | sed 's/^# \{0,1\}//'
}

main() {
    while (($#)); do
        case $1 in
            --hours) WINDOW_HOURS=${2:-}; shift 2 || break ;;
            --php) PHP_VER=${2:-}; shift 2 || break ;;
            -h | --help) usage; exit 0 ;;
            *) usage >&2; exit 2 ;;
        esac
    done
    if ! [[ $WINDOW_HOURS =~ ^[1-9][0-9]*$ ]]; then
        echo "--hours must be a positive whole number" >&2
        exit 2
    fi
    if [[ -n $PHP_VER && ! $PHP_VER =~ ^[0-9]+\.[0-9]+$ ]]; then
        echo "--php must look like 8.3" >&2
        exit 2
    fi
    # Without root, other users' processes, sockets and logs are invisible and every check passes.
    if ((EUID != 0)); then
        echo "Run as root: sudo $0 $*" >&2
        exit 2
    fi

    SINCE="$WINDOW_HOURS hours ago"
    SINCE_EPOCH=$(date -d "$SINCE" +%s)
    WINDOW_MINUTES=$((WINDOW_HOURS * 60))
    WEB_UIDS=""
    local u
    for u in ${WEB_USERS//,/ }; do
        WEB_UIDS+="$(id -u "$u" 2>/dev/null) "
    done

    check_segfaults
    check_shells
    check_fpm_children
    check_exe_paths
    check_sockets
    check_temp_files
    check_webshells
    check_persistence

    echo "=========================================="
    echo "Window: last $WINDOW_HOURS hours | PHP-FPM: ${PHP_VER:-all versions}"
    if ((${#REASONS[@]} == 0)); then
        echo "Result: [ALL GOOD]"
        echo "No signs of exploit activity, crashes, or post-exploitation binaries detected."
        echo "=========================================="
        exit 0
    fi
    echo "Result: [POSSIBLE COMPROMISED]"
    echo "Indicators flagged:"
    local r
    for r in "${REASONS[@]}"; do
        echo " - $r"
    done
    echo "=========================================="
    exit 1
}

# Sourcing the file loads the checks without running them (handy for testing one check).
[[ ${BASH_SOURCE[0]} == "$0" ]] && main "$@"
