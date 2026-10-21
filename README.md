# check_compromise

A read-only Bash script that looks for signs an attacker got code running on a PHP web server through PHP-FPM.

It is built for Laravel Forge servers on **Ubuntu 22.04 or newer** and checks **every installed PHP version**. It changes nothing on the server: it only reads processes, connections, logs and files.

```
==========================================
Window: last 24 hours | PHP-FPM: all versions
Result: [ALL GOOD]
No signs of exploit activity, crashes, or post-exploitation binaries detected.
==========================================
```

## Install

Download the script with `curl`:

```bash
curl -fsSL -o check_compromise.sh \
  https://raw.githubusercontent.com/emilianotisato/check_compromise/main/check_compromise.sh
```

Read it before you run it. It is short, and you will run it as root:

```bash
less check_compromise.sh
```

Make it executable:

```bash
chmod +x check_compromise.sh
```

You only need `chmod` once. If you'd rather skip it, run the script through Bash instead: `sudo bash check_compromise.sh`.

## Run

```bash
sudo ./check_compromise.sh
```

The script **must run as root**. Without root it can't see other users' processes, connections or logs, so it would miss everything. It exits with an error instead of giving you a false `[ALL GOOD]`.

### Options

| Option | What it does | Default |
| --- | --- | --- |
| `--hours N` | How far back the time-based checks look | `24` |
| `--php X.Y` | Check only this PHP-FPM version, e.g. `8.3` | all installed versions |
| `-h`, `--help` | Show usage | |

```bash
sudo ./check_compromise.sh --hours 72 --php 8.3
```

### Exit codes

`0` means nothing was found. `1` means at least one indicator was flagged. `2` means the script could not run (bad option, or not root).

## What it checks

1. **PHP-FPM crashes** in the time window. A segfault can mean someone is trying a memory-corruption exploit.
2. **Shells or network tools with no terminal**, run by `www-data` or `forge`. This is what a reverse shell looks like.
3. **Programs started by a PHP-FPM worker.** A web shell runs its commands this way.
4. **Web-user programs running from `/tmp`**, from memory only, or from a deleted file. Malware often deletes itself after starting.
5. **Connections to unusual ports** owned by `www-data` or `forge`.
6. **New executables or scripts** in `/tmp`, `/var/tmp` or `/dev/shm`.
7. **Web shells in Laravel apps.** A stock app has no PHP in `public/` besides `index.php`, and none in `storage/` besides compiled views. This check ignores the time window: a planted shell stays a problem until you remove it.
8. **Changed SSH keys or crontabs.** Attackers use them to get back in later.

## Run it on a schedule

Copy the script somewhere permanent:

```bash
sudo install -m 755 check_compromise.sh /usr/local/bin/check_compromise.sh
```

Then add a cron entry, for example every 6 hours:

```bash
echo '0 */6 * * * root /usr/local/bin/check_compromise.sh --hours 7 >> /var/log/check_compromise.log 2>&1' \
  | sudo tee /etc/cron.d/check_compromise
```

**Keep `--hours` longer than the time between runs.** Here it runs every 6 hours and looks back 7. With a shorter window, anything that happens in the gap is never checked.

## Tuning

Set these environment variables to fit your server:

| Variable | What it controls | Default |
| --- | --- | --- |
| `WEB_USERS` | Users the web app runs as | `www-data,forge` |
| `SITES_ROOT` | Folder that holds your Laravel apps | `/home/forge` |
| `ALLOWED_PORTS` | Remote ports web users may connect to | `22 25 80 443 465 587 3306 5432 6379` |
| `ALLOW_CMD_REGEX` | Command lines that are known to be fine | artisan, composer, sendmail |

```bash
sudo ALLOWED_PORTS="22 80 443 3306 6379 11211" ./check_compromise.sh
```

`sudo` drops most environment variables, so put them after `sudo` as shown.

## False alarms you may see

- **A deploy is running.** Forge deploy scripts look like shells with no terminal. Run the script again once the deploy finishes.
- **Your app runs other programs**, such as image or PDF tools. They show up as PHP-FPM children. Add them to `ALLOW_CMD_REGEX`.
- **You added an SSH key or cron job** in the window. The persistence check flags it. That's fine if you made the change yourself.
- **Your app talks to a service on another port**, such as Memcached or an external API. Add the port to `ALLOWED_PORTS`.

## Limits

`[ALL GOOD]` means none of these checks fired. It is **not proof the server is clean**.

- A reverse shell over port 443 looks like normal web traffic, so the connection check misses it.
- Anything older than `--hours` is invisible to the crash, temp-file and persistence checks.
- An attacker who already has root can hide from any script that runs on the same machine.

## If it flags something

1. Don't reboot the server yet. A reboot wipes running processes and memory, which you need for investigating.
2. Note the PIDs and paths in the output.
3. Look at each process with `ls -l /proc/<PID>/exe` and `cat /proc/<PID>/cmdline | tr '\0' ' '`.
4. If it looks real, take the server off the network and treat it as compromised. That means rotating credentials and rebuilding from a clean image.
