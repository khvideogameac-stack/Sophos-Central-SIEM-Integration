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
"""Generate synthetic Sophos Central events for testing the Wazuh pipeline.

Useful because a quiet tenant produces nothing to test with: you can wait an
hour on the real feed and still not know whether your rules fire.

The events are built in Sophos's own shape and then passed through the same
promote_wazuh_fields() the collector uses, so what comes out here is what the
collector would write for equivalent real events. A hand-written fixture would
drift from that transformation the first time it changed.

Everything generated is marked as synthetic and unmistakable:

  - hostnames prefixed TEST-
  - IPs from 203.0.113.0/24 and 198.51.100.0/24, reserved by RFC 5737 for
    documentation and guaranteed not to belong to anyone
  - a test_event field, so you can find and remove them later

Examples:

    # Look at them
    python3 tools/generate_test_events.py

    # Check a rule fires, without touching the pipeline
    python3 tools/generate_test_events.py --count 1 | sudo /var/ossec/bin/wazuh-logtest

    # Inject into the live feed and watch Wazuh react
    python3 tools/generate_test_events.py --append log/sophos_central.json
"""

import argparse
import datetime
import json
import os
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import siem  # noqa: E402

# RFC 5737 documentation ranges. Never routable, never anyone's real host.
TEST_NET_1 = "203.0.113."
TEST_NET_2 = "198.51.100."


def scenario(event_type, severity, location, ip, user, name, group, rule, **extra):
    """Build a scenario entry.
    Arguments:
        rule {int}: the rule id this event is expected to match
    """
    entry = {
        "type": event_type,
        "severity": severity,
        "location": location,
        "ip": ip,
        "user": user,
        "name": name,
        "group": group,
        "expect_rule": rule,
    }
    entry.update(extra)
    return entry


# One outbreak burst plus one of each interesting event type. The burst is
# five identical detections on a single endpoint because that is what the
# correlation rule keys on - a lone detection could never exercise it.
OUTBREAK_BURST = [
    scenario(
        "Event::Endpoint::Threat::Detected",
        "high",
        "TEST-WKS-01",
        TEST_NET_1 + "11",
        "testuser1@example.com",
        "EICAR-AV-Test",
        "MALWARE",
        100210,
    )
] * 5

SCENARIOS = OUTBREAK_BURST + [
    scenario(
        "Event::Endpoint::Threat::CleanupFailed",
        "high",
        "TEST-WKS-02",
        TEST_NET_1 + "12",
        "testuser2@example.com",
        "Troj/Agent-TEST",
        "MALWARE",
        100212,
    ),
    scenario(
        "Event::Endpoint::Threat::CommandAndControlDetected",
        "very_high",
        "TEST-SRV-01",
        TEST_NET_2 + "21",
        "svc_test@example.com",
        "C2 callback blocked",
        "MALWARE",
        100214,
    ),
    scenario(
        "Event::Endpoint::Threat::PuaDetected",
        "medium",
        "TEST-WKS-03",
        TEST_NET_1 + "13",
        "testuser3@example.com",
        "PUA/TestTool",
        "MALWARE",
        100213,
    ),
    scenario(
        "Event::Endpoint::DataLossPreventionUserAllowed",
        "medium",
        "TEST-WKS-04",
        TEST_NET_1 + "14",
        "testuser4@example.com",
        "Confidential test document",
        "DATA_LOSS_PREVENTION",
        100220,
    ),
    scenario(
        "Event::Endpoint::Threat::Detected",
        "high",
        "TEST-SRV-02",
        TEST_NET_2 + "22",
        "svc_test2@example.com",
        "Troj/TestAlert",
        "MALWARE",
        100216,
        datastream="alert",
        product="endpoint",
    ),
]

# Sophos Central also emits a newer Core* naming scheme, and which one a tenant
# sends appears to depend on the platform and product version. Rules written
# only against the legacy Threat::* names silently fall through to the severity
# fallback on a tenant using these, which downgrades a malware detection to a
# generic informational alert. These scenarios keep that from regressing.
CORE_SCENARIOS = [
    scenario(
        "Event::Endpoint::CoreDetection",
        "medium",
        "TEST-WKS-10",
        TEST_NET_1 + "30",
        "testuser10@example.com",
        "Mal/Generic-TEST",
        "MALWARE",
        100210,
    ),
    scenario(
        "Event::Endpoint::CoreCleanFailed",
        "medium",
        "TEST-WKS-11",
        TEST_NET_1 + "31",
        "testuser11@example.com",
        "Mal/Generic-TEST",
        "MALWARE",
        100212,
    ),
    scenario(
        "Event::Endpoint::CorePuaCleanFailed",
        "medium",
        "TEST-WKS-12",
        TEST_NET_1 + "32",
        "testuser12@example.com",
        "Generic Reputation PUA",
        "MALWARE",
        100212,
    ),
    scenario(
        "Event::Endpoint::CorePuaDetection",
        "medium",
        "TEST-WKS-13",
        TEST_NET_1 + "33",
        "testuser13@example.com",
        "Generic Reputation PUA",
        "MALWARE",
        100213,
    ),
    scenario(
        "Event::Endpoint::CorePuaClean",
        "low",
        "TEST-WKS-14",
        TEST_NET_1 + "34",
        "testuser14@example.com",
        "Generic Reputation PUA",
        "MALWARE",
        100211,
    ),
    scenario(
        "Event::Endpoint::CoreDismissed",
        "low",
        "TEST-WKS-15",
        TEST_NET_1 + "35",
        "testuser15@example.com",
        "Detection dismissed",
        "MALWARE",
        100217,
    ),
    scenario(
        "Event::Endpoint::Application::Blocked",
        "medium",
        "TEST-WKS-16",
        TEST_NET_1 + "36",
        "testuser16@example.com",
        "Blocked application",
        "APPLICATION_CONTROL",
        100233,
    ),
    scenario(
        "Event::Endpoint::UpdateRebootRequired",
        "low",
        "TEST-WKS-17",
        TEST_NET_1 + "37",
        "testuser17@example.com",
        "Reboot to complete update",
        "UPDATING",
        100234,
    ),
]

SCENARIOS = SCENARIOS + CORE_SCENARIOS

# Human readable expectation per rule id, for --explain.
RULE_DESCRIPTIONS = {
    100210: "malware detected (level 12); 4+ of these also trigger 100290 outbreak",
    100212: "malware cleanup failed (level 13)",
    100213: "potentially unwanted application (level 10)",
    100214: "command and control (level 12)",
    100220: "DLP user allowed transfer (level 8)",
    100216: "malware ALERT via alert stream (level 13)",
    100241: "high severity alert (level 13)",
    100211: "malware cleaned up (level 6)",
    100217: "detection dismissed (level 5)",
    100233: "application blocked (level 5)",
    100234: "reboot required to complete update (level 3)",
}


def build_event(scenario, when):
    """Build one event in Sophos's own shape, before any Wazuh reshaping.
    Arguments:
        scenario {dict}: entry from SCENARIOS
        when {datetime}: event timestamp
    Returns:
        dict -- raw Sophos style event
    """
    stamp = when.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    event = {
        "severity": scenario["severity"],
        "location": scenario["location"],
        "endpoint_type": "server" if "SRV" in scenario["location"] else "computer",
        "endpoint_id": str(uuid.uuid4()),
        "customer_id": "00000000-0000-0000-0000-000000000000",
        "source_info": {"ip": scenario["ip"]},
        "type": scenario["type"],
        "id": str(uuid.uuid4()),
        "group": scenario["group"],
        "datastream": scenario.get("datastream", "event"),
        "when": stamp,
        "created_at": stamp,
        "source": scenario["user"],
        "name": scenario["name"],
        # Marks the event as synthetic so it can be found and removed later.
        "test_event": True,
    }
    if "product" in scenario:
        event["product"] = scenario["product"]
    return event


def generate(count, spacing_seconds):
    """Yield (json_line, expectation) pairs.
    Arguments:
        count {int}: how many events to produce
        spacing_seconds {int}: seconds between consecutive event timestamps
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    for i in range(count):
        scenario = SCENARIOS[i % len(SCENARIOS)]
        # Walk backwards from now so the newest event is the last one written,
        # and the whole burst sits inside the correlation rules' timeframe.
        when = now - datetime.timedelta(seconds=(count - i - 1) * spacing_seconds)
        raw = build_event(scenario, when)
        # The same call the collector makes. Generating the output shape by
        # hand here would let the fixtures drift from the real transformation.
        shaped = siem.promote_wazuh_fields(raw)
        rule = scenario["expect_rule"]
        expect = "%s %s" % (rule, RULE_DESCRIPTIONS.get(rule, ""))
        yield json.dumps(shaped, ensure_ascii=False), expect.strip()


def main():
    parser = argparse.ArgumentParser(
        description="Generate synthetic Sophos Central events in wazuh format.",
        epilog="Events are marked test_event=true and use RFC 5737 IPs.",
    )
    parser.add_argument(
        "-n", "--count", type=int, default=10, help="events to generate (default 10)"
    )
    parser.add_argument(
        "-a",
        "--append",
        metavar="FILE",
        help="append to FILE instead of stdout, e.g. the collector's output file",
    )
    parser.add_argument(
        "--spacing",
        type=int,
        default=5,
        help="seconds between event timestamps (default 5)",
    )
    parser.add_argument(
        "--explain",
        action="store_true",
        help="print which rule each event should match, to stderr",
    )
    args = parser.parse_args()

    if args.count < 1:
        parser.error("--count must be at least 1")

    lines = list(generate(args.count, args.spacing))

    if args.append:
        with open(args.append, "a", encoding="utf-8") as f:
            for line, _ in lines:
                f.write(line + "\n")
        print(
            "Appended %s test events to %s" % (len(lines), args.append),
            file=sys.stderr,
        )
        print(
            "Remove them later with:  grep -v '\"test_event\": true' %s"
            % args.append,
            file=sys.stderr,
        )
    else:
        for line, _ in lines:
            print(line)

    if args.explain:
        print("\nExpected matches:", file=sys.stderr)
        for i, (_, expect) in enumerate(lines, 1):
            print("  %2d. %s" % (i, expect), file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
