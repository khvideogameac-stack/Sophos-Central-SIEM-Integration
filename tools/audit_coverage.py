#!/usr/bin/env python3

# Copyright 2019-2021 Sophos Limited
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
# compliance with the License.
# You may obtain a copy of the License at:  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing permissions and limitations under the
# License.
#
"""Report how every event type in your feed is being scored.

Sophos Central emits different event type names depending on product version
and platform, so a ruleset that matches one tenant can silently miss another:
the events still alert, but through the generic severity fallback, which
downgrades a malware detection to whatever severity Sophos happened to set. It
looks like everything is working.

This lists every event type actually present in your collector output, the
rule that matches it, and flags the ones falling through to the fallback so
coverage gaps are visible rather than inferred.

    python3 tools/audit_coverage.py log/sophos_staging.json

It does not need Wazuh installed and does not touch the manager.
"""

import argparse
import collections
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import rule_match  # noqa: E402


def main():
    parser = argparse.ArgumentParser(
        description="Show which rule matches each event type in a collector output file."
    )
    parser.add_argument("file", help="collector output file (format = wazuh)")
    parser.add_argument(
        "--rules",
        help="rule file to check against (defaults to the one in this repo)",
    )
    parser.add_argument(
        "--gaps-only",
        action="store_true",
        help="list only event types with no specific rule",
    )
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print("No such file: %s" % args.file, file=sys.stderr)
        return 1

    rules = rule_match.load_child_rules(args.rules)
    levels = {r[0]: r[1] for r in rules}

    counts = collections.Counter()
    unshaped = 0
    total = 0
    with open(args.file, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            total += 1
            if event.get("test_event"):
                continue
            # Without the integration marker the base rule never matches, so
            # nothing in the ruleset can fire for this line.
            if event.get("integration") != "sophos-central":
                unshaped += 1
                continue
            matched = rule_match.first_matching_rule(event, rules)
            counts[(event.get("type"), event.get("severity"), matched)] += 1

    if unshaped:
        print(
            "WARNING: %s of %s lines lack integration=sophos-central.\n"
            "         Those were written with format=json, not format=wazuh,\n"
            "         and no rule in this set can match them.\n" % (unshaped, total)
        )

    if not counts:
        print("No scoreable events found in %s" % args.file)
        return 1

    rows = []
    for (etype, severity, matched), n in counts.items():
        is_gap = matched in rule_match.FALLBACK_RULES or matched is None
        rows.append((n, etype, severity, matched, levels.get(matched), is_gap))
    rows.sort(key=lambda r: (-r[0], str(r[1])))

    print("%6s  %-46s %-9s %-12s %s" % ("count", "event type", "severity", "rule/level", "coverage"))
    print("-" * 104)
    gap_total = 0
    for n, etype, severity, matched, level, is_gap in rows:
        if args.gaps_only and not is_gap:
            continue
        if matched is None:
            rule_txt, cov = "none", "NO ALERT"
        else:
            rule_txt = "%s / L%s" % (matched, level)
            cov = "fallback only" if is_gap else "specific"
        if is_gap:
            gap_total += n
        print(
            "%6d  %-46s %-9s %-12s %s"
            % (n, str(etype)[:46], str(severity), rule_txt, cov)
        )

    scored = sum(r[0] for r in rows)
    print()
    if gap_total:
        print(
            "%s of %s events (%.0f%%) have no specific rule and are scored only by\n"
            "the severity Sophos assigned them. That is fine for routine types, but\n"
            "check the list above for anything security relevant - a detection scored\n"
            "this way alerts at the wrong level."
            % (gap_total, scored, 100.0 * gap_total / scored)
        )
    else:
        print("Every event type present has a specific rule.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
