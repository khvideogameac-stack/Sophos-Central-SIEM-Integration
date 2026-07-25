# Project log: Sophos Central to Wazuh integration

**Author:** AlRasedah
**Period:** 2026-07-25
**Branch:** `claude/sophos-wazuh-integration-3tawsf`
**Base:** fork of Sophos-Central-SIEM-Integration v2.1.0

A chronological record of the work and every problem encountered, kept so the
next person does not rediscover the same traps. Operational reference lives in
[`../HANDOFF.md`](../HANDOFF.md).

Final state: 30 files changed, 3,744 insertions, 16 commits, 116 tests passing,
every event type in the live feed covered by a specific rule.

---

## Part 1 — Starting point

The repo was upstream v2.1.0 plus some third-party logging changes. It had
**no Wazuh content at all**: no rules, no decoders, no `ossec.conf` guidance,
no documentation. It was already running in production feeding
`log/result.txt` into Wazuh with `log_format json`.

An audit of the codebase found four defects that made it unsafe to run
unattended, all confirmed by reproduction rather than inspection:

| # | Defect | Consequence |
| --- | --- | --- |
| 1 | `raise SystemExit()` with no argument | Exits **0**. A failed collection was indistinguishable from a successful one to cron |
| 2 | Retry loop fell off the end | `request_url` returned `None` after exhausting retries; surfaced as `TypeError` in `json.loads` frames away |
| 3 | Only `HTTPError` caught | DNS failures, refused connections and TLS timeouts were never retried and killed the run |
| 4 | Non-atomic state writes | A crash mid-write left a truncated state file that blocked every subsequent run |

Verified:

```
$ python3 -c 'raise SystemExit()'; echo $?
0
```

Also found: no run lock (overlapping cron runs race the API cursor), no request
timeout, unbounded output file growth, `datetime.utcnow()` deprecated,
plaintext secrets only, and 10 of 55 unit tests failing on arrival because the
fork changed function signatures without updating tests.

---

## Part 2 — Build

### The core design decision

Wazuh's JSON decoder promotes a fixed set of top-level key names into its
static fields. Those get dedicated rule options (`<srcip>`, `<user>`), GeoIP
enrichment, and active-response substitution. Everything else is only reachable
as `data.<name>`.

Sophos puts the two most useful values where that cannot happen: the client IP
at `source_info.ip`, the account at `source`. So `format = wazuh` copies them
to `srcip` and `dstuser`, adds an `integration` marker for rules to key on and
a numeric `severity_num`, and moves aside top-level keys that would collide
with a Wazuh static field while carrying an object.

Copies rather than moves, so anything built against the original paths keeps
working.

### Delivered

- `format = wazuh` output mode
- Ruleset, IDs 100200–100299
- `ossec.conf` snippet, sample events, install docs
- All four reliability defects fixed, plus run lock, request timeout, log
  rotation, env-var secrets, config defaults
- Fixed the 10 pre-existing test failures; added coverage for the new code
- CI on Python 3.9–3.13 plus rule XML validation

Backward compatibility verified explicitly: a `config.ini` carrying none of the
new options still runs and produces byte-identical `format = json` output.

---

## Part 3 — Deployment, and everything that went wrong

This is the useful part. Each problem is recorded with its symptom, actual
cause, and fix.

### 3.1 Exit code 5 on the very first run

**Symptom:** `Another collector run holds .../siem_sophos.json.lock` — but no
other process existed.

**Cause:** a defect in the new code. `RunLock.acquire()` caught every
`OSError` and returned `False`, so a permission error on the lock file was
reported as contention.

**Fix:** opening the lock file and locking it are now separate failures. Only
`EACCES`/`EAGAIN` *from `flock` itself* means contention; anything else raises
`LockUnavailable` and reports as exit 4 with the real errno.

**Lesson:** an error path that collapses two distinct causes into one message
sends the operator hunting for the wrong thing.

### 3.2 Output going to the wrong file

**Symptom:** logs still landing in `result.txt`.

**Cause:** `filename` had not been changed in `config.ini`. Mundane — but it
exposed a worse defect introduced during the build: adding config defaults made
a missing config file **silent**, because `ConfigParser.read()` ignores a file
that does not exist. A wrong `-c` path now produced a healthy-looking run
writing to `result.txt` in `json` format, since those were the defaults. Before
the defaults it crashed loudly.

**Fix:** `Config` verifies the file exists and that `[login]` is present,
probing before defaults are applied. Startup now logs the resolved absolute
config path with the format and filename it produced.

**Lesson:** defaults that improve upgrade safety can destroy failure
visibility. Every default needs a matching validity check.

### 3.3 "We have to add sudo or the cron won't work"

**Cause:** not the script. The redirect target `/var/log/sophos-siem.log` is
not writable by `it0`, so the shell failed before Python started.

**Why `sudo` would have been worse:** running as root makes `log/`, `state/`
and the lock file root-owned, breaking the next unprivileged run — the exact
churn behind 3.1. `sudo` in a user crontab usually fails anyway: no TTY, and it
wants a password.

**Fix:** dedicated log directory owned by the run user, plus a logrotate config
whose `su`/`create` lines keep ownership across rotations.

### 3.4 "None of these worked"

Several rounds of individual diagnostic commands had produced no conclusion.
Wrong approach — replaced with `tools/diagnose_wazuh.sh`, which checks all
eight links in one run and prints PASS/FAIL per step.

Its `<localfile>` check parses `ossec.conf` **as XML** rather than grepping,
because a commented-out block matches a grep but is invisible to Wazuh —
worse than not checking at all. Verified against four fixtures: path mismatch,
commented-out block, wrong `log_format`, correct setup.

**Lesson:** when three rounds of ad-hoc commands have not converged, stop and
build the instrument.

### 3.5 What the diagnostic found

Two of its own bugs, and the real cause.

Its bugs: `wazuh-logtest -t` is unsupported on this version (now uses
`wazuh-analysisd -t`), and `grep -c ... || echo 0` produced the two-line value
`"0\n0"` and broke an integer comparison.

**The real cause:**

| Time | Event |
| --- | --- |
| 11:39 | Output file written — 1 line |
| 11:42 | logcollector read it — **no Sophos rules existed yet** |
| 12:15 | Rules installed |
| 12:16, 12:21 | logcollector reopened the file |

**logcollector records its byte position and only reads what is appended
after it.** That single line was consumed when no rule could match it.
Restarting does not re-read old lines. Nothing had been appended since.

### 3.6 Path mismatch — the root cause of several days of confusion

**Symptom:** everything healthy, no new data reaching Wazuh.

**Cause:** the collector had been moved to `/opt`, but Wazuh's `<localfile>`
still pointed at `/home/it0/.../log/result.txt`. Two installs, diverged paths.
Worse, a test-event injection had written *into the old file*, so that file
looked correct while being entirely the wrong one.

**Confirmed from the alert data:** 18 alerts still arriving from `/home/it0`,
matched by a pre-existing third-party ruleset (`100802`/`100803`), and all 18
event IDs also present in the `/opt` feed — genuine duplicate ingestion.

**Lesson:** when moving an install, `filename` in `config.ini` and
`<location>` in `ossec.conf` must be changed together. Nothing reports the
mismatch. Giving the new output a distinct filename makes a half-finished
migration obvious instead of silent.

### 3.7 The significant defect: wrong event names

**Symptom:** rules firing, alerts arriving, everything apparently working.

**Cause:** the rules were written against the legacy
`Event::Endpoint::Threat::*` names taken from `name_mapping.py`. **This tenant
emits `Event::Endpoint::Core*`.** Every real malware event fell through to the
generic severity fallback.

The specific malware rules had only ever fired on the synthetic test events —
which used the legacy names. **The test generator was confirming the ruleset
against its own assumption rather than against reality.**

Measured on 252 real events:

| Event | Was | Should be |
| --- | --- | --- |
| `CorePuaCleanFailed` × 27 | L7 | **L13** |
| `CoreCleanFailed` × 7 | L7 | **L13** |
| `CoreDetection` × 7 | L7 | **L12** |
| `CorePuaDetection` × 29 | L7 | **L10** |

**34 events where cleanup failed — endpoints still infected — were alerting at
level 7.** 144 of 252 alerts got a more accurate severity after the fix.

**Fix:** rules match both naming schemes; the generator covers `Core*` too.

**Lesson:** a test fixture derived from the same assumption as the code under
test proves nothing. This is why `tools/audit_coverage.py` exists — it reads
the *actual* feed and flags types reaching only the fallback.

### 3.8 Unreadable descriptions

**Symptom:** "only benign things are showing."

**Cause:** descriptions rendered `$(type)` — the machine event name — while
Sophos's own `name` field carried exactly what an analyst needs and went
unused.

```
Sophos Central: Event::Endpoint::CoreDetection on Mohamed-Hamoda
Sophos malware: Malware detected: 'Mal/Generic-S' at 'D:\...\crack.zip' [Mohamed-Hamoda]
```

Combined with 3.7 — level 7, generic wording — real malware genuinely looked
like routine noise on the dashboard.

**Fix:** all descriptions use `$(name)` with a short category prefix. Verified
`name` and `location` are present on all 266 events first, so no description
can render a literal `$(name)`.

### 3.9 Replay amplification

The replay tool appends to the file it reads, so a second run selected the
first run's output too: 72 → 144 → 288 per run.

**Fix:** deduplicate on Sophos event id. Verified three consecutive replays
append 72 each, inode preserved.

### 3.10 A malformed file shipped to the branch

The noise-suppression sample contained `--light` inside an XML comment. `--` is
not permitted there; installing it would have stopped `wazuh-manager` loading
its ruleset.

**Why it got through:** the validator globbed `*.xml` but not `*.xml.sample`.

**Fix:** validator covers `.xml.sample`. That surfaced a second bug — the
`if_sid` check was per-file, so the overrides file chaining off `100200` in the
main file was flagged as dangling. Wazuh loads the rules directory as one
ruleset, so references now resolve across all files.

### 3.11 Judgement reversed on dismissals

`CoreDismissed` was initially listed as noise to suppress, reasoning from
volume alone (72/day).

The data reversed it: **all 72 dismissals landed on a single endpoint — the
same one carrying 34 failed cleanups and two dozen cracks and keygens.** That
is someone clearing detections instead of remediating them.

**Fix:** the suppression block carries a warning, and rule `100293` alerts on
10+ dismissals against one endpoint in an hour.

**Lesson:** volume is not noise. Tuning by frequency without asking *where* the
frequency concentrates discards signal.

### 3.12 Ingestion time versus event time

Recurring source of "where did my alerts go". **Wazuh stamps alerts at
ingestion time.** A 24-hour backfill lands as one spike at the moment it ran.
Alerts with `data.when` spanning Jul 24 10:41 → Jul 25 11:18 all carried
`timestamp` 13:41–14:20 the same day. Looking at a recent window showed almost
nothing.

**Fix:** documented. Sort and filter on `data.when` for real event time.

### 3.13 Last coverage gap

`tools/audit_coverage.py` against the live feed found `Event::Endpoint::Device::Blocked`
(the USB block) reaching only the fallback at level 3. Added rules 100236
(device blocked, L5, T1200) and 100237 (device allowed in monitor-only mode,
L6 — deliberately *higher*, because the device was not stopped), plus 100235
for routine maintenance types.

Result: **every event type in the live feed has a specific rule.**

---

## Part 4 — Security finding

**Host `Mohamed-Hamoda` (`10.105.0.92`), user `MOHAMED-HAMODA\Hamoda`, plus an
associated laptop.**

142 events in one day, 23 distinct threat/path pairs, **34 failed cleanups**
(27 PUA, 7 malware) unremediated at handoff.

- `Mal/Generic-S` in `E:\Program\_Getintopc.com_AutoCAD_2024_English_Win_64-bit\Crack.rar`
- Keygens and cracks: AutoCAD 2018/2020, Photoshop 2020, KMS activator,
  Registry Reviver, MikroTik
- **72 detections marked as resolved** on the same host

Open at handoff. See [`../HANDOFF.md`](../HANDOFF.md) §8.

---

## Part 5 — Commits

| Hash | Summary |
| --- | --- |
| `fd69a7d` | Add Wazuh integration and harden the collector for unattended runs |
| `7e3a044` | Distinguish an unopenable lock file from genuine contention |
| `6015c09` | Fail loudly on a missing or malformed config file |
| `5e2ca1c` | Document cron permissions and correct stale-lock troubleshooting |
| `115485b` | Add synthetic event generator and offline rule-matching tests |
| `9b994bc` | Document the moved-install trap and inode-swap cleanup hazard |
| `811290f` | Add a one-shot pipeline diagnostic |
| `88f2125` | Fix diagnostic bugs and explain the empty-alerts case |
| `175c955` | Match the Core* event names Sophos Central actually emits |
| `5aeafb5` | Add a replay tool for re-scoring events after a rule change |
| `bb0f7d8` | Make alert descriptions readable and ship optional noise suppression |
| `84ff749` | Make replays idempotent |
| `524c6bd` | Warn against suppressing dismissals, and correlate them instead |
| `39417ee` | Fix malformed overrides sample and close the validator gap |
| `71b9150` | Add a coverage audit so ruleset gaps are visible instead of inferred |
| `1fa73a1` | Add device control and routine maintenance rules |

---

## Part 6 — What this cost, and what would have prevented it

Most time went not to building the integration but to diagnosing failures that
produced **no error anywhere**. In every case the pipeline reported success:

- Wrong output path — collector healthy, Wazuh healthy, no data
- Wrong event names — rules firing, alerts arriving, wrong severity
- Consumed log position — file correct, rules correct, no alerts
- Wrong descriptions — alerts present, unreadable

Three tools now cover those blind spots, and should be run in this order
whenever something looks wrong:

1. `tools/diagnose_wazuh.sh` — is the chain connected?
2. `tools/audit_coverage.py` — is every event type scored correctly?
3. `wazuh-logtest` on a real line — does a rule match actual data?

The most transferable lesson: **a working pipeline and a correct pipeline are
different things.** Events arriving, rules firing and alerts appearing tells
you nothing about whether the severity is right. Only a tool that compares the
live feed against the ruleset can answer that, and building it earlier would
have saved most of the time spent here.
