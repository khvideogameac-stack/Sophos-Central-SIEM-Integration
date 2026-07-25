# Feeding Sophos Central into Wazuh

End-to-end setup for running this collector as an unattended feed into Wazuh.
The Wazuh-side files it refers to live in [`wazuh/`](../wazuh/), which has its
own README covering the rules in detail.

## Choosing an ingestion path

Write to a file and have logcollector read it. Do not use `filename = syslog`
for Wazuh:

- Python's `SysLogHandler` emits `<PRI>` followed by the raw message with no
  RFC3164/5424 header, so Wazuh's syslog parser cannot pre-decode `hostname` or
  `program_name` from it.
- UDP truncates silently. Sophos alert payloads carrying `raw_data` routinely
  exceed a single datagram, and Wazuh's syslog input caps around 6 KB regardless.
- You lose `full_log`, which for the file path is the whole original line.

With `log_format json` Wazuh parses each line into `data.*` fields with no
decoder to write or maintain.

## Where to run the collector

Either works, logcollector runs on managers and agents alike:

| Placement | When it fits | Notes |
| --- | --- | --- |
| On the Wazuh manager | Single manager, no dedicated collector host | `<localfile>` goes in the manager's `ossec.conf` |
| On a Wazuh agent | Collector already lives elsewhere, or you want it off the manager | `<localfile>` goes in the agent's `ossec.conf`; rules always go on the manager |

## 1. Configure the collector

```ini
# config.ini
client_id     = <from Sophos Central API Credentials Management>
client_secret = <from Sophos Central API Credentials Management>
tenant_id     = <your tenant id>

format   = wazuh
filename = sophos_central.json
endpoint = all

max_log_file_size_mb  = 100
log_file_backup_count = 5

logging_level = INFO
```

`format = wazuh` is what makes the shipped rules fire — it adds the
`integration` marker they key on, and copies `source_info.ip` to `srcip` and
`source` to `dstuser` so Wazuh promotes them to static fields with GeoIP and
`<srcip>`/`<user>` matching. See [`wazuh/README.md`](../wazuh/README.md) for
why that matters.

#### Migrating an existing install to a new directory

If you are moving the collector - a fresh clone in `/opt` replacing an older
one in a home directory, say - the output path changes, and Wazuh keeps
reading the old one until you tell it otherwise. The symptom is a collector
that looks entirely healthy while no new Sophos data reaches the dashboard.

Check the two paths agree before anything else:

```bash
# What the collector writes
grep -E '^\s*filename\s*=' /opt/sophos-siem/config.ini

# What Wazuh reads
sudo grep -n '<location>' /var/ossec/etc/ossec.conf
```

Three things to get right when you move:

1. **Copy `config.ini` and `state/`.** Both are gitignored, so a fresh clone
   has neither. Without the state file the first run re-fetches 12 hours and
   duplicates all of it.
2. **Disable the old install's schedule.** Two collectors with separate state
   files both fetch everything, and Wazuh does not deduplicate.
3. **Repoint `<localfile>` and restart the manager.**

Giving the new output a distinct filename rather than reusing `result.txt`
makes a half-finished migration obvious instead of silent.

#### Migrating from `format = json`

Field names change, so check anything you already built before switching.
`format = json` runs events through the CEF key mapping on the way out;
`format = wazuh` keeps Sophos's own names and adds the promoted ones:

| Sophos field | `format = json` emits | `format = wazuh` emits |
| --- | --- | --- |
| `location` | `dhost` | `location` |
| `source` | `suser` | `source` + `dstuser` |
| `when` | `end` | `when` |
| `created_at` | `rt` | `created_at` |
| `source_info.ip` | `source_info.ip` | `source_info.ip` + `srcip` |

So a rule or dashboard keyed on `data.dhost` needs to move to `data.location`.
The shipped rules already use the `format = wazuh` names. If you would rather
not migrate, keep `format = json` and rewrite the rules' field names instead —
but you lose `srcip` promotion and the GeoIP enrichment that depends on it.

Both formats are read by Wazuh with the same `<log_format>json</log_format>`,
so the `<localfile>` block does not change.

#### Keeping secrets out of config.ini

The environment wins over `config.ini`:

```bash
export SOPHOS_CLIENT_ID=...
export SOPHOS_CLIENT_SECRET=...
export SOPHOS_TENANT_ID=...
```

Leave `logging_level` at `INFO`. `DEBUG` logs full API responses.

## 2. Schedule it

A systemd timer is preferable to cron: you get exit codes in
`systemctl status`, and journald keeps the collector's own logs separate from
the event output.

```ini
# /etc/systemd/system/sophos-siem.service
[Unit]
Description=Sophos Central SIEM collector
After=network-online.target

[Service]
Type=oneshot
User=sophos-siem
Environment=SOPHOS_SIEM_HOME=/opt/sophos-siem
WorkingDirectory=/opt/sophos-siem
ExecStart=/usr/bin/python3 /opt/sophos-siem/siem.py
# Secrets from a root-only file rather than config.ini or the unit
EnvironmentFile=/etc/sophos-siem/secrets.env
```

```ini
# /etc/systemd/system/sophos-siem.timer
[Unit]
Description=Run the Sophos Central SIEM collector every 5 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
AccuracySec=30s

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl enable --now sophos-siem.timer
```

Overlapping runs are safe: the collector takes an advisory lock on the state
file and a second run exits 5 without collecting.

### With cron instead

```
*/5 * * * * cd /opt/sophos-siem && SOPHOS_SIEM_HOME=/opt/sophos-siem /usr/bin/python3 siem.py >> /var/log/sophos-siem/collector.log 2>&1
```

The `cd` is required: without it the script resolves paths against cron's
working directory.

### Pick one user and stay with it

The collector does not need root, and running it as root once is enough to
cause trouble later: `log/`, `state/` and the lock file become root-owned, and
the next unprivileged run fails on them. Do not put `sudo` in a crontab to work
around that - in a user crontab it usually fails anyway, since there is no TTY
and sudo wants a password.

If a cron entry only fails as an unprivileged user, check the redirect target
before blaming the script. `/var/log/` is not writable by a normal user, so the
shell fails before Python starts:

```bash
sudo mkdir -p /var/log/sophos-siem
sudo chown "$USER":"$USER" /var/log/sophos-siem
sudo chown -R "$USER":"$USER" /opt/sophos-siem   # undo any earlier root-owned files
```

Rotate that log, keeping ownership across rotations:

```
# /etc/logrotate.d/sophos-siem
/var/log/sophos-siem/collector.log {
    weekly
    rotate 4
    compress
    missingok
    notifempty
    su sophos-siem sophos-siem
    create 0644 sophos-siem sophos-siem
}
```

Without the `su` and `create` lines the rotated file reverts to root ownership
and the next run cannot write to it.

Wazuh reads the event output regardless of which user wrote it, since
`wazuh-logcollector` runs as root.

## 3. Point Wazuh at the output

Merge into `/var/ossec/etc/ossec.conf` on whichever host runs the collector:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/opt/sophos-siem/log/sophos_central.json</location>
</localfile>
```

Rotation is rename-and-create, which logcollector follows automatically.

## 4. Install the rules

```bash
sudo cp wazuh/rules/0910-sophos_central_rules.xml /var/ossec/etc/rules/
sudo chown root:wazuh /var/ossec/etc/rules/0910-sophos_central_rules.xml
sudo chmod 660 /var/ossec/etc/rules/0910-sophos_central_rules.xml
sudo systemctl restart wazuh-manager
```

## 5. Verify

```bash
# Collector runs clean
python3 siem.py; echo "exit: $?"     # 0

# Output is one JSON object per line with srcip promoted
tail -1 log/sophos_central.json | python3 -m json.tool | grep -E 'srcip|integration'

# Ruleset loads
sudo /var/ossec/bin/wazuh-logtest -t

# A known event matches the rule you expect
head -1 wazuh/samples/sample_events.jsonl | sudo /var/ossec/bin/wazuh-logtest
```

The last command should report rule **100210** at level 12.

## Exit codes

Meaningful now, so a wrapper or `systemctl status` can distinguish failures.
Defined in [`exit_codes.py`](../exit_codes.py):

| Code | Meaning |
| ---- | ------- |
| 0 | Success, including "no new events" |
| 1 | Config missing or invalid |
| 2 | Sophos rejected the credentials, or the tenant could not be resolved |
| 3 | Could not reach the Sophos API or the syslog target |
| 4 | State file unusable, needs an operator |
| 5 | Another run holds the lock (not an error) |

## Monitoring the feed itself

No events looks exactly like a quiet day, so the rules cannot tell you the
collector died. Watch the state file's `lastRunAt` instead:

```bash
#!/usr/bin/env bash
# Alert if no tenant has been collected in 30 minutes
python3 - <<'EOF'
import json, sys, time
state = json.load(open("/opt/sophos-siem/state/siem_sophos.json"))
stale = [t for t, v in state.get("tenants", {}).items()
         if time.time() - v.get("lastRunAt", 0) > 1800]
if stale:
    sys.exit("Sophos collection stale for: %s" % ", ".join(stale))
EOF
```

## Troubleshooting

**Events in the file but no alerts in Wazuh.** Check `format = wazuh` in
`config.ini` — with `format = json` the `integration` field is absent and rule
100200 never matches, so nothing downstream fires. Confirm with
`grep -c integration log/sophos_central.json`.

**`srcip` empty, no GeoIP.** The event had no `source_info.ip`; many event
types genuinely lack one. If it is present in the raw event but not promoted,
check the promoted-name list for your Wazuh version.

**Nothing read at all.** Check, in this order:

1. **The paths agree.** Compare `filename` in `config.ini` against
   `<location>` in `ossec.conf`. After moving the collector these diverge
   silently, and everything else looks healthy.
2. **The Wazuh user can reach the file.**
   `sudo -u wazuh test -r <path>` - it needs execute on every parent directory,
   which bites under `/opt` and under home directories.
3. **logcollector opened it.** Restart the manager, then
   `grep <path> /var/ossec/logs/ossec.log`. That line is only written at
   startup, so an empty grep on a long-running manager proves nothing.

**Alerts stopped after cleaning up the file.** Rewriting the output file with
`mv` gives it a new inode, and logcollector keeps reading the old, unlinked
one. Truncate in place instead - `cat tmp > file` rather than `mv tmp file` -
or restart the manager.

**Duplicate events after an incident.** The state file was reset, so the run
re-fetched the last 12 hours. Expected; Wazuh does not deduplicate.

**Collector exits 5 every run.** Another run genuinely holds the lock. Check
`cat state/siem_sophos.json.lock` for the holder's pid. A lock file left behind
by a killed run does not block anything - the kernel releases `flock` when the
holder dies - so deleting the file is not the fix.

**Collector exits 4 with "Cannot open lock file".** Permissions, not
contention. The state directory is not writable by the user running the
collector, usually because an earlier run under `sudo` left root-owned files
behind. See "Pick one user and stay with it" above.

**Cron entry does nothing, but it works by hand with sudo.** Test the redirect
target separately - `>> /var/log/something.log` fails for an unprivileged user
before Python runs, which looks like the script failing. Adding `sudo` to the
crontab is the wrong fix; see above.
