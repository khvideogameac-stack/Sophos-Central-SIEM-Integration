#!/usr/bin/env bash
#
# Copyright 2019-2021 Sophos Limited
# Licensed under the Apache License, Version 2.0 (the "License").
#
# One-shot diagnostic for the Sophos -> Wazuh pipeline.
#
# Checks every link in the chain in order and prints PASS/FAIL for each, so a
# broken pipeline is identified in one run instead of a dozen round trips.
#
# Usage:
#   sudo bash tools/diagnose_wazuh.sh [/path/to/collector]
#
# Run with sudo: several checks need to read /var/ossec.

set -u

SIEM_DIR="${1:-/opt/Sophos-Central-SIEM-Integration}"
# Overridable so the script can be exercised against a fixture.
OSSEC_DIR="${OSSEC_DIR:-/var/ossec}"
OSSEC_CONF="$OSSEC_DIR/etc/ossec.conf"

PASS=0
FAIL=0
WARN=0

pass() { printf '  [ OK ]  %s\n' "$*"; PASS=$((PASS + 1)); }
fail() { printf '  [FAIL]  %s\n' "$*"; FAIL=$((FAIL + 1)); }
warn() { printf '  [WARN]  %s\n' "$*"; WARN=$((WARN + 1)); }
info() { printf '          %s\n' "$*"; }
head1() { printf '\n=== %s ===\n' "$*"; }

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this with sudo - several checks read /var/ossec." >&2
fi

head1 "1. Collector"

if [ -d "$SIEM_DIR" ]; then
    pass "collector directory: $SIEM_DIR"
else
    fail "collector directory not found: $SIEM_DIR"
    echo
    echo "Pass the correct path as an argument. Aborting."
    exit 1
fi

CONFIG="$SIEM_DIR/config.ini"
if [ -f "$CONFIG" ]; then
    pass "config.ini present"
else
    fail "config.ini missing at $CONFIG"
fi

get_cfg() {
    # Last non-commented assignment wins, matching ConfigParser.
    grep -E "^[[:space:]]*$1[[:space:]]*=" "$CONFIG" 2>/dev/null \
        | tail -1 | cut -d= -f2- | tr -d ' \t\r'
}

FORMAT=$(get_cfg format)
FILENAME=$(get_cfg filename)

if [ "$FORMAT" = "wazuh" ]; then
    pass "format = wazuh"
else
    fail "format = '${FORMAT:-unset}' - the shipped rules need 'wazuh'"
    info "with format=json the 'integration' field is absent and rule 100200 never matches"
fi

info "filename = ${FILENAME:-unset}"

case "$FILENAME" in
    syslog|stdout)
        fail "filename = $FILENAME - this script assumes file output"
        OUTPUT=""
        ;;
    "")
        fail "filename not set"
        OUTPUT=""
        ;;
    *)
        OUTPUT="$SIEM_DIR/log/$FILENAME"
        ;;
esac

head1 "2. Collector output file"

if [ -n "$OUTPUT" ] && [ -f "$OUTPUT" ]; then
    pass "output file exists: $OUTPUT"
    info "$(ls -l "$OUTPUT")"
    info "lines: $(wc -l < "$OUTPUT")  inode: $(stat -c %i "$OUTPUT")"
    info "last modified: $(stat -c %y "$OUTPUT")"

    LAST_LINE=$(tail -1 "$OUTPUT" 2>/dev/null)
    if [ -n "$LAST_LINE" ]; then
        if printf '%s' "$LAST_LINE" | grep -q '"integration"'; then
            pass "last line carries the 'integration' marker"
        else
            fail "last line has no 'integration' field - written in the wrong format"
        fi
        if printf '%s' "$LAST_LINE" | python3 -c 'import json,sys; json.loads(sys.stdin.read())' 2>/dev/null; then
            pass "last line is valid JSON"
        else
            fail "last line is not valid JSON"
        fi
    else
        warn "output file is empty - nothing has been collected yet"
    fi

    if command -v runuser >/dev/null 2>&1 && id wazuh >/dev/null 2>&1; then
        if runuser -u wazuh -- test -r "$OUTPUT" 2>/dev/null; then
            pass "readable by the wazuh user"
        else
            fail "NOT readable by the wazuh user"
            info "needs execute on every parent dir: chmod o+x $SIEM_DIR $SIEM_DIR/log"
        fi
    else
        warn "cannot test wazuh-user readability (no runuser, or no wazuh user)"
    fi
elif [ -n "$OUTPUT" ]; then
    fail "output file does not exist: $OUTPUT"
    info "contents of $SIEM_DIR/log:"
    ls -l "$SIEM_DIR/log" 2>/dev/null | sed 's/^/          /' || info "  (no log directory)"
fi

head1 "3. Wazuh installation"

if [ -d "$OSSEC_DIR" ]; then
    pass "Wazuh present at $OSSEC_DIR"
else
    fail "no Wazuh install at $OSSEC_DIR"
    exit 1
fi

if [ -r "$OSSEC_CONF" ]; then
    pass "ossec.conf readable"
else
    fail "cannot read $OSSEC_CONF (run with sudo)"
fi

if [ -x "$OSSEC_DIR/bin/wazuh-control" ]; then
    RUNNING=$("$OSSEC_DIR/bin/wazuh-control" status 2>/dev/null)
    if printf '%s' "$RUNNING" | grep -q 'logcollector is running'; then
        pass "wazuh-logcollector is running"
    else
        fail "wazuh-logcollector is NOT running"
        printf '%s\n' "$RUNNING" | sed 's/^/          /'
    fi
    if printf '%s' "$RUNNING" | grep -q 'analysisd is running'; then
        pass "wazuh-analysisd is running"
    else
        fail "wazuh-analysisd is NOT running"
    fi
else
    warn "wazuh-control not found, skipping daemon checks"
fi

head1 "4. localfile configuration"

# Parsed as XML rather than grepped, so a commented-out block is not counted
# as configuration. ossec.conf has multiple root elements, hence the wrapper.
LOCATIONS=$(python3 - "$OSSEC_CONF" <<'PYEOF' 2>/dev/null
import sys, xml.etree.ElementTree as ET
try:
    raw = open(sys.argv[1], encoding="utf-8", errors="replace").read()
    root = ET.fromstring("<wrapper>" + raw + "</wrapper>")
except Exception as e:
    print("PARSE_ERROR:%s" % e)
    sys.exit(0)
for lf in root.iter("localfile"):
    loc = lf.find("location")
    fmt = lf.find("log_format")
    if loc is not None:
        print("%s\t%s" % ((loc.text or "").strip(),
                          (fmt.text or "").strip() if fmt is not None else "?"))
PYEOF
)

if printf '%s' "$LOCATIONS" | grep -q '^PARSE_ERROR:'; then
    fail "ossec.conf is not well-formed XML"
    printf '%s\n' "$LOCATIONS" | sed 's/^/          /'
elif [ -z "$LOCATIONS" ]; then
    fail "no <localfile> blocks found at all"
else
    info "active <localfile> entries (comments excluded):"
    printf '%s\n' "$LOCATIONS" | sed 's/^/            /'

    MATCH=""
    while IFS=$'\t' read -r loc fmt; do
        [ -z "$loc" ] && continue
        if [ "$loc" = "$OUTPUT" ]; then
            MATCH="$loc"
            if [ "$fmt" = "json" ]; then
                pass "localfile matches the output path, log_format=json"
            else
                fail "localfile matches the path but log_format='$fmt', needs 'json'"
            fi
        fi
    done <<< "$LOCATIONS"

    if [ -z "$MATCH" ]; then
        fail "NO active localfile points at $OUTPUT"
        info "this is the usual cause: the collector writes one path,"
        info "Wazuh watches another. Fix ossec.conf, then restart wazuh-manager."
    fi
fi

head1 "5. Rules"

RULEFILE="$OSSEC_DIR/etc/rules/0910-sophos_central_rules.xml"
if [ -f "$RULEFILE" ]; then
    pass "rule file installed"
    info "$(ls -l "$RULEFILE")"
    # wazuh-analysisd -t is the portable way to validate the ruleset.
    # wazuh-logtest grew a -t flag only in later versions; on older ones it is
    # a python wrapper that rejects the argument.
    if [ -x "$OSSEC_DIR/bin/wazuh-analysisd" ]; then
        if ANALYSISD_OUT=$("$OSSEC_DIR/bin/wazuh-analysisd" -t 2>&1); then
            pass "ruleset loads without error"
        else
            fail "ruleset failed to load:"
            printf '%s\n' "$ANALYSISD_OUT" | tail -15 | sed 's/^/          /'
        fi
    else
        warn "wazuh-analysisd not found, skipping ruleset validation"
    fi
else
    fail "rule file NOT installed at $RULEFILE"
    info "cp $SIEM_DIR/wazuh/rules/0910-sophos_central_rules.xml $OSSEC_DIR/etc/rules/"
fi

head1 "6. Does a real event match a rule?"

if [ -n "${LAST_LINE:-}" ] && [ -x "$OSSEC_DIR/bin/wazuh-logtest" ]; then
    LOGTEST_OUT=$(printf '%s\n' "$LAST_LINE" | "$OSSEC_DIR/bin/wazuh-logtest" 2>&1)
    RULE_HIT=$(printf '%s' "$LOGTEST_OUT" | grep -oE "id: *'[0-9]+'" | head -1)
    if [ -n "$RULE_HIT" ]; then
        pass "logtest matched rule $RULE_HIT"
    else
        fail "logtest matched no rule"
    fi
    printf '%s\n' "$LOGTEST_OUT" | tail -25 | sed 's/^/          /'
else
    warn "skipped (no event line available, or logtest missing)"
fi

head1 "7. Alerts actually produced"

# grep -c prints 0 and exits 1 when there are no matches, so `|| echo 0`
# produced the two-line value "0\n0" and broke the integer test.
ALERTS="$OSSEC_DIR/logs/alerts/alerts.json"
if [ -r "$ALERTS" ]; then
    N_SOPHOS=$(grep -c 'sophos_central' "$ALERTS" 2>/dev/null || true)
    N_TEST=$(grep -c 'test_event' "$ALERTS" 2>/dev/null || true)
    N_SOPHOS=${N_SOPHOS:-0}
    N_TEST=${N_TEST:-0}
    if [ "$N_SOPHOS" -gt 0 ]; then
        pass "$N_SOPHOS Sophos alerts in alerts.json ($N_TEST synthetic)"
        info "most recent:"
        grep 'sophos_central' "$ALERTS" | tail -3 \
            | python3 -c '
import json,sys
for l in sys.stdin:
    try: a=json.loads(l)
    except Exception: continue
    r=a.get("rule",{})
    print("            %s  level %s  %s" % (r.get("id"), r.get("level"), r.get("description")))
' 2>/dev/null
    else
        fail "no Sophos alerts have ever been generated"
        # The usual cause is not a broken rule but a file whose existing lines
        # were already consumed before the rules were installed. logcollector
        # records its position and only reads what is appended after it;
        # restarting the manager does not make it re-read old lines.
        if [ -n "${RULE_HIT:-}" ]; then
            info "but logtest DOES match (see section 6), so the rules are fine."
            info "logcollector only reads lines appended after its saved position,"
            info "so anything written before the rules were installed is never"
            info "re-read. Append a new event and it will alert:"
            info "  python3 $SIEM_DIR/tools/generate_test_events.py --append $OUTPUT"
        fi
    fi
else
    warn "cannot read $ALERTS"
fi

# A level 3 alert is silently discarded if the threshold was raised, which
# looks identical to a rule that never fired.
ALERT_LEVEL=$(python3 - "$OSSEC_CONF" <<'PYEOF' 2>/dev/null
import sys, xml.etree.ElementTree as ET
try:
    raw = open(sys.argv[1], encoding="utf-8", errors="replace").read()
    root = ET.fromstring("<wrapper>" + raw + "</wrapper>")
except Exception:
    sys.exit(0)
for alerts in root.iter("alerts"):
    lvl = alerts.find("log_alert_level")
    if lvl is not None and lvl.text:
        print(lvl.text.strip())
PYEOF
)
if [ -n "$ALERT_LEVEL" ]; then
    if [ "$ALERT_LEVEL" -le 3 ]; then
        pass "log_alert_level = $ALERT_LEVEL (low severity Sophos events will alert)"
    else
        warn "log_alert_level = $ALERT_LEVEL"
        info "rules 100201 (level 3) and 100230 (level 4) are below this and"
        info "will never reach alerts.json or the dashboard."
    fi
else
    info "log_alert_level not set, Wazuh default is 3"
fi

if printf '%s' "${JSONOUT:-}" >/dev/null; then :; fi
JSONOUT=$(grep -o '<jsonout_output>[^<]*' "$OSSEC_CONF" 2>/dev/null | tail -1 | cut -d'>' -f2)
if [ "${JSONOUT:-yes}" = "no" ]; then
    warn "jsonout_output = no - alerts.json is not written (alerts.log still is)"
fi

head1 "8. logcollector activity"

OSSEC_LOG="$OSSEC_DIR/logs/ossec.log"
if [ -r "$OSSEC_LOG" ] && [ -n "$OUTPUT" ]; then
    HITS=$(grep -F "$OUTPUT" "$OSSEC_LOG" | tail -5)
    if [ -n "$HITS" ]; then
        pass "ossec.log mentions the output file"
        printf '%s\n' "$HITS" | sed 's/^/          /'
    else
        warn "ossec.log never mentions $OUTPUT"
        info "only logged at manager startup, so this alone is not proof."
        info "restart wazuh-manager and re-run to make it conclusive."
    fi
    ERRS=$(grep -iE 'error|critical' "$OSSEC_LOG" | tail -5)
    if [ -n "$ERRS" ]; then
        warn "recent errors in ossec.log:"
        printf '%s\n' "$ERRS" | sed 's/^/          /'
    fi
fi

head1 "Summary"
printf '  %s passed, %s failed, %s warnings\n\n' "$PASS" "$FAIL" "$WARN"
if [ "$FAIL" -gt 0 ]; then
    echo "  Fix the [FAIL] items top to bottom - the earliest one usually"
    echo "  explains everything below it."
    exit 1
fi
echo "  Chain looks intact. If the dashboard is still empty, the problem is"
echo "  indexing or the dashboard time range, not the pipeline."
exit 0
