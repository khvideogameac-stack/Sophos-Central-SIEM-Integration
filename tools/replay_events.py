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
"""Re-feed already-collected events so updated rules score them again.

Wazuh alerts are immutable: fixing a rule does not re-score alerts already
generated. logcollector also tracks its position in the output file and never
re-reads what it has already consumed. So after a rule change the only way to
get correct alerts for past events is to append those events again.

This appends to the file logcollector is watching, which produces a second
alert for each replayed event. The original, wrongly scored alert stays in the
index - see docs/wazuh.md for removing those if you want a clean dashboard.

Replayed events keep their original data.when, so event time is preserved even
though the new alert is stamped at replay time.

Examples:

    # What would be replayed, without doing it
    python3 tools/replay_events.py log/sophos_staging.json --dry-run

    # Replay only the malware events whose severity was wrong
    python3 tools/replay_events.py log/sophos_staging.json --preset malware

    # Replay specific types
    python3 tools/replay_events.py log/sophos_staging.json \
        --types Event::Endpoint::CoreDetection Event::Endpoint::CoreCleanFailed
"""

import argparse
import collections
import json
import os
import sys
import tempfile

# The event types whose scoring changed when the Core* names were added to the
# ruleset. Replaying these is what turns a level 7 "generic medium" alert into
# the level 12/13 malware alert it should always have been.
PRESETS = {
    "malware": [
        "Event::Endpoint::CoreDetection",
        "Event::Endpoint::CoreCleanFailed",
        "Event::Endpoint::CorePuaCleanFailed",
        "Event::Endpoint::CorePuaDetection",
        "Event::Endpoint::CorePuaClean",
        "Event::Endpoint::Threat::Detected",
        "Event::Endpoint::Threat::CleanupFailed",
        "Event::Endpoint::Threat::PuaCleanupFailed",
        "Event::Endpoint::Threat::HIPSCleanupFailed",
        "Event::Endpoint::Threat::PuaDetected",
    ],
    "rescored": [
        # Everything whose rule changed, including the high volume low value
        # types. Produces a lot of duplicate alerts; prefer "malware".
        "Event::Endpoint::CoreDetection",
        "Event::Endpoint::CoreCleanFailed",
        "Event::Endpoint::CorePuaCleanFailed",
        "Event::Endpoint::CorePuaDetection",
        "Event::Endpoint::CorePuaClean",
        "Event::Endpoint::CoreDismissed",
        "Event::Endpoint::Application::Blocked",
        "Event::Endpoint::UpdateRebootRequired",
    ],
}


def load_events(path):
    """Read the collector's output file.
    Returns:
        (events, skipped) -- parsed events and count of unparsable lines
    """
    events = []
    skipped = 0
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append((line, json.loads(line)))
            except json.JSONDecodeError:
                skipped += 1
    return events, skipped


def main():
    parser = argparse.ArgumentParser(
        description="Re-append collected events so updated rules score them again."
    )
    parser.add_argument("file", help="the collector output file Wazuh is watching")
    parser.add_argument(
        "--types", nargs="+", metavar="TYPE", help="only replay these event types"
    )
    parser.add_argument(
        "--preset",
        choices=sorted(PRESETS),
        help="replay a predefined set: 'malware' (recommended) or 'rescored'",
    )
    parser.add_argument(
        "--all", action="store_true", help="replay every event in the file"
    )
    parser.add_argument(
        "--skip-test-events",
        action="store_true",
        default=True,
        help="do not replay synthetic events (default)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="report what would be replayed and exit",
    )
    args = parser.parse_args()

    if not (args.types or args.preset or args.all):
        parser.error("choose one of --types, --preset or --all")

    if not os.path.isfile(args.file):
        print("No such file: %s" % args.file, file=sys.stderr)
        return 1

    events, skipped = load_events(args.file)
    print("Read %s events from %s" % (len(events), args.file))
    if skipped:
        print("  (%s unparsable lines skipped)" % skipped)

    wanted = set(args.types or []) | set(PRESETS.get(args.preset, []))

    selected = []
    for line, event in events:
        if args.skip_test_events and event.get("test_event"):
            continue
        if args.all or event.get("type") in wanted:
            selected.append(line)

    if not selected:
        print("\nNothing matched. Types present in the file:")
        counts = collections.Counter(e.get("type") for _, e in events)
        for t, n in counts.most_common():
            print("  %5d  %s" % (n, t))
        return 1

    counts = collections.Counter(json.loads(l).get("type") for l in selected)
    print("\nWould replay %s events:" % len(selected))
    for t, n in counts.most_common():
        print("  %5d  %s" % (n, t))

    if args.dry_run:
        print("\nDry run, nothing written.")
        return 0

    # Append rather than rewrite: replacing the file changes its inode and
    # logcollector would keep reading the old one.
    with open(args.file, "a", encoding="utf-8") as f:
        for line in selected:
            f.write(line + "\n")
        f.flush()
        os.fsync(f.fileno())

    print("\nAppended %s events to %s" % (len(selected), args.file))
    print("Wazuh should produce new alerts within a few seconds.")
    print("Confirm the rules were reloaded first, or they will be scored the")
    print("same wrong way again:")
    print("  sudo /var/ossec/bin/wazuh-control restart")
    return 0


if __name__ == "__main__":
    sys.exit(main())
