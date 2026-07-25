# Handoff: Sophos Central to Wazuh integration

**Author:** AlRasedah
**Date:** 2026-07-25
**Branch:** `claude/sophos-wazuh-integration-3tawsf`
**Status:** Working in production. Events flowing, rules firing, coverage complete.

This document is what a new engineer needs to run, debug and extend the
integration. For the full record of how it got here and every problem hit along
the way, see [`docs/PROJECT_LOG.md`](docs/PROJECT_LOG.md).

---

## 1. What this is

A fork of Sophos's official SIEM collector, extended to feed Sophos Central
events and alerts into Wazuh. Three parts:

1. **Collector** (`siem.py`) — polls the Sophos Central API every 5 minutes and
   writes one JSON object per line to a file.
2. **Wazuh logcollector** — tails that file with `log_format json`.
3. **Ruleset** (`wazuh/rules/`) — scores the decoded events.

The important addition over upstream is `format = wazuh`, which reshapes events
so Wazuh's JSON decoder promotes the client IP and account into its static
fields. Without it you get no GeoIP, no `<srcip>` matching, and none of the
shipped rules fire.

---

## 2. Production layout

| Thing | Location |
| --- | --- |
| Collector | `/opt/Sophos-Central-SIEM-Integration` |
| Config | `/opt/Sophos-Central-SIEM-Integration/config.ini` |
| Output read by Wazuh | `/opt/Sophos-Central-SIEM-Integration/log/sophos_staging.json` |
| State (API cursor) | `/opt/Sophos-Central-SIEM-Integration/state/siem_sophos.json` |
| Rules | `/var/ossec/etc/rules/0910-sophos_central_rules.xml` |
| Wazuh config | `/var/ossec/etc/ossec.conf` (`<localfile>` block) |
| Runs as | `it0`, via that user's crontab, every 5 minutes |

**The output filename is `sophos_staging.json` for historical reasons** — it
began as a staging file during migration and was never renamed. It is
production. If you rename it, change `filename` in `config.ini` **and**
`<location>` in `ossec.conf` together, or the feed silently stops.

### Config essentials

```ini
format   = wazuh              # NOT json. Nothing works without this.
filename = sophos_staging.json
endpoint = all
logging_level = INFO          # DEBUG logs full API responses
```

Credentials can come from `SOPHOS_CLIENT_ID` / `SOPHOS_CLIENT_SECRET` /
`SOPHOS_TENANT_ID`, which override `config.ini`.

---

## 3. Health checks

Run this first, always. It checks all eight links in the chain:

```bash
sudo bash /opt/Sophos-Central-SIEM-Integration/tools/diagnose_wazuh.sh
```

Quick manual checks:

```bash
# Collector runs clean
cd /opt/Sophos-Central-SIEM-Integration && python3 siem.py; echo "exit: $?"

# Feed is live (mtime should be within 5 minutes)
ls -l state/siem_sophos.json

# Every event type has a rule
python3 tools/audit_coverage.py log/sophos_staging.json

# Alerts reaching Wazuh
sudo grep -c sophos_central /var/ossec/logs/alerts/alerts.json
```

### Exit codes

`siem.py` returns meaningful codes so a scheduler can alert on failure.

| Code | Meaning |
| --- | --- |
| 0 | Success, including "no new events" |
| 1 | Config missing or invalid |
| 2 | Credentials rejected / tenant unresolvable |
| 3 | Cannot reach the Sophos API or syslog target |
| 4 | State file unusable, needs an operator |
| 5 | Another run holds the lock (not an error) |

---

## 4. The ruleset

IDs `100200`–`100299`. Full list in
[`wazuh/README.md`](wazuh/README.md).

| Rule | Level | Fires on |
| --- | --- | --- |
| 100200 | 0 | Base rule. Never alerts, everything chains off it |
| 100210 | 12 | Malware detected |
| 100212 | 13 | **Cleanup failed — endpoint still infected** |
| 100213 | 10 | PUA detected |
| 100214 | 12 | Command and control |
| 100216 | 13 | Malware on the alert stream |
| 100217 | 5 | Detection dismissed |
| 100220 | 8 | DLP transfer allowed |
| 100233 | 5 | Application blocked |
| 100236 | 5 | Device/USB blocked |
| 100237 | 6 | Device allowed, monitor-only mode |
| 100290 | 14 | Outbreak: 4+ detections, one endpoint, 10 min |
| 100291 | 14 | Worm: same threat, multiple endpoints |
| 100201/2/3 | 3/7/10 | Severity fallback for anything unmatched |

### Three things to know before editing

**Order matters.** All rules are children of 100200, and Wazuh takes the first
matching sibling. Specific rules come first, severity fallback last. Insert new
specific rules *above* 100203.

**`<field>` uses osregex, not PCRE.** `\.` means "any character", a bare `.` is
a literal dot. The wildcard is written `\.*`.

**Sophos emits two naming schemes.** Legacy `Event::Endpoint::Threat::*` and
newer `Event::Endpoint::Core*`. This tenant sends `Core*`. Rules match both —
do not remove either.

### After any rule change

```bash
python3 tools/validate_wazuh_rules.py          # XML, ids, levels, dangling refs
python3 -m pytest tests/ -q                    # 116 tests, includes rule matching
sudo cp wazuh/rules/0910-sophos_central_rules.xml /var/ossec/etc/rules/
sudo systemctl restart wazuh-manager
python3 tools/audit_coverage.py log/sophos_staging.json
```

---

## 5. Tools

| Tool | Purpose |
| --- | --- |
| `tools/diagnose_wazuh.sh` | One-shot health check of the whole chain |
| `tools/audit_coverage.py` | Which rule scores each event type; flags gaps |
| `tools/generate_test_events.py` | Synthetic events for testing without waiting |
| `tools/replay_events.py` | Re-score past events after a rule change |
| `tools/validate_wazuh_rules.py` | Static checks on the rule XML |
| `tools/rule_match.py` | Offline rule matcher, shared by audit and tests |

Test the pipeline end to end without waiting for real events:

```bash
python3 tools/generate_test_events.py --append log/sophos_staging.json
```

Synthetic events use `TEST-` hostnames, RFC 5737 IPs, and carry
`test_event: true`. Remove them with:

```bash
TMP=$(mktemp) && grep -v '"test_event": true' log/sophos_staging.json > "$TMP" \
  && cat "$TMP" > log/sophos_staging.json && rm "$TMP"
```

Use `cat >`, not `mv`. `mv` gives the file a new inode and logcollector keeps
reading the old one.

---

## 6. Traps that have already cost time

Read these before debugging anything. Each one cost hours.

**Wazuh timestamps alerts at ingestion, not event time.** A backfill of 24
hours of history lands as one spike at the moment you ran it. If alerts seem
missing, widen the dashboard time range before assuming anything is broken.
Sort on `data.when` for real event time.

**logcollector only reads lines appended after its saved position.** Fixing a
rule does not re-score existing alerts, and restarting the manager does not
re-read old lines. Use `tools/replay_events.py`.

**Add `data.name` as a dashboard column.** Without it you see only
`rule.description`, and the threat name and file path stay hidden. This is the
single biggest usability win.

**Path mismatch is silent.** `filename` in `config.ini` and `<location>` in
`ossec.conf` must agree exactly. When they diverge, everything looks healthy
and no data arrives.

**Never `sudo` the cron entry.** It makes `log/`, `state/` and the lock file
root-owned, breaking the next unprivileged run. If cron fails but manual runs
work, check the redirect target — `/var/log/` is not writable by `it0`.

**A rule can fire and still be wrong.** Events reaching only the severity
fallback still alert, just at the wrong level. `audit_coverage.py` is the only
thing that makes that visible.

---

## 7. Open items

**The old install at `/home/it0/Sophos-Central-SIEM-Integration` may still be
running.** It duplicates collection, and a pre-existing third-party ruleset
(`100802`/`100803`, groups `sophos,central`) alerts on it separately. Remove
its cron entry and its `<localfile>` block, then decide whether to keep that
ruleset at all — running both against one feed gives two alerts per event at
different levels.

**`log/sophos_central.json` is a stale 4-line leftover** in the old `json`
format. Nothing reads it. Delete it so it cannot confuse a future diagnosis.

**Log rotation is off.** `max_log_file_size_mb = 0` in `config.ini`. Set it to
`100` now that events are flowing.

**Noise suppression is available but not installed.**
`wazuh/rules/0911-sophos_overrides.xml.sample` silences routine types. Read the
comments first — the `CoreDismissed` block is a judgement call, see below.

**Consider a systemd timer instead of cron.** Exit codes show up in
`systemctl status` instead of being buried in a log file. Unit files are in
[`docs/wazuh.md`](docs/wazuh.md).

---

## 8. Security finding, open at handoff

**Host `Mohamed-Hamoda` (`10.105.0.92`), user `MOHAMED-HAMODA\Hamoda`, plus an
associated laptop.**

In a single day: 142 events, 23 distinct threat/path pairs, **34 failed
cleanups** (27 PUA, 7 malware) that remain unremediated.

- `Mal/Generic-S` in `E:\Program\_Getintopc.com_AutoCAD_2024_English_Win_64-bit\Crack.rar`
- Keygens and cracks across AutoCAD 2018/2020, Photoshop 2020, KMS activator,
  Registry Reviver, MikroTik

**72 `CoreDismissed` events — "Malware marked as resolved" — all on this one
host, the same host carrying the 34 failed cleanups.** Someone has been
clearing detections rather than remediating them.

This is why `CoreDismissed` should *not* be suppressed in this environment,
despite its volume. Rule `100293` in the overrides sample alerts on 10+
dismissals against one endpoint in an hour; keep it even if individual
dismissals are silenced.

Find it:

```
data.location: "Mohamed-Hamoda"
```

---

## 9. Deployment from scratch

Full walkthrough in [`docs/wazuh.md`](docs/wazuh.md). Summary:

1. Clone, copy `config.ini` and `state/` from the existing install
2. Set `format = wazuh`, `filename`, credentials
3. `python3 siem.py` — expect exit 0
4. Install rules to `/var/ossec/etc/rules/`, restart the manager
5. Add the `<localfile>` block from `wazuh/ossec.conf.d/`, restart
6. Verify with `tools/diagnose_wazuh.sh` and `tools/audit_coverage.py`
7. Add the cron entry (no `sudo`, log somewhere the run user owns)
