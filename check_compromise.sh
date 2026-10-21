#!/usr/bin/env bash
# Read-only audit script: strictly checks for active CVE-2026-109618 / php2shell exploit behavior

COMPROMISED=0
REASONS=()

# 1. Check for PHP-FPM Segmentation Faults logged in the last 2 hours
# Uses journalctl with strict time-bounding so historical crashes are ignored
RECENT_SEGFAULTS=$(sudo journalctl -u "php*-fpm" -k -g "php-fpm.*segfault|SIGSEGV" --since "2 hours ago" --no-pager 2>/dev/null | tail -n 5)
if [ -n "$RECENT_SEGFAULTS" ]; then
    COMPROMISED=1
    REASONS+=("PHP-FPM segmentation fault occurred within the last 2 hours (potential memory corruption)")
fi

# 2. Check for unauthorized detached shells or reverse-shell network tools
# - Ignores processes attached to valid interactive terminals (pts/*)
# - Excludes standard Laravel Forge background workers (Horizon, artisan, systemd, nginx)
SUSPICIOUS_PROCS=$(ps -u www-data,forge -o pid,user,tty,cmd 2>/dev/null | \
    grep -E "\b(bash|sh|zsh|dash|python|python3|perl|ruby|nc|ncat|netcat|socat)\b" | \
    grep -v " pts/" | \
    grep -v -E "(artisan|horizon|systemd|sd-pam|nginx|composer|npm|node|check_compromise)")

if [ -n "$SUSPICIOUS_PROCS" ]; then
    COMPROMISED=1
    REASONS+=("Detached shell or network binary running under www-data/forge without a TTY: $SUSPICIOUS_PROCS")
fi

# 3. Check for unauthorized web shells spawned directly by php-fpm (Parent Process Check)
PHP_FPM_PIDS=$(pgrep -d',' -f "php-fpm: pool" 2>/dev/null)
if [ -n "$PHP_FPM_PIDS" ]; then
    CHILDREN_OF_FPM=$(pgrep -P "$PHP_FPM_PIDS" 2>/dev/null)
    if [ -n "$CHILDREN_OF_FPM" ]; then
        COMPROMISED=1
        REASONS+=("PHP-FPM spawned unauthorized child process(es): PIDs $CHILDREN_OF_FPM")
    fi
fi

# 4. Check for active outbound connections to non-standard ports from web users
# Flags external connections that are NOT standard web, database, or SSH ports (80, 443, 22, 3306, 5432, 6379)
SUSPICIOUS_SOCKETS=$(sudo ss -tunp | grep -E "users:.*\b(php-fpm|www-data)\b" | grep -vE "(:80|:443|:22|:3306|:5432|:6379|127\.0\.0\.1)" | grep "ESTAB")
if [ -n "$SUSPICIOUS_SOCKETS" ]; then
    COMPROMISED=1
    REASONS+=("PHP-FPM maintains an unexpected outbound TCP socket: $SUSPICIOUS_SOCKETS")
fi

# 5. Check for newly written executable scripts in /tmp or /dev/shm (created in last 2 hours)
RECENT_TEMP_BINS=$(find /tmp /dev/shm -maxdepth 2 -type f \( -perm -111 -o -name "*.sh" -o -name "*.so" \) -mmin -120 2>/dev/null)
if [ -n "$RECENT_TEMP_BINS" ]; then
    COMPROMISED=1
    REASONS+=("Executable scripts or binaries placed in /tmp or /dev/shm in the last 2 hours: $RECENT_TEMP_BINS")
fi

# --- Result Output ---
if [ $COMPROMISED -eq 0 ]; then
    echo "=========================================="
    echo "Result: [ALL GOOD]"
    echo "No signs of exploit activity, crashes, or post-exploitation binaries detected."
    echo "=========================================="
    exit 0
else
    echo "=========================================="
    echo "Result: [POSSIBLE COMPROMISED]"
    echo "Indicators flagged:"
    for r in "${REASONS[@]}"; do
        echo " - $r"
    done
    echo "=========================================="
    exit 1
fi
