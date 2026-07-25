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
"""Check generated events match the rules they claim to.

This is an APPROXIMATION of Wazuh's rule engine, not a substitute for it. It
models the two things most likely to break silently when the ruleset is
edited - sibling evaluation order, and the osregex field patterns - and
nothing else. It knows nothing about frequency, timeframe, same_field or
if_matched_sid.

wazuh-logtest on a real manager remains the authority. What this catches is a
rule reordered so that the severity fallback shadows a specific rule, which is
invisible until someone notices alerts arriving at the wrong level.
"""

import os
import re
import sys
import unittest
import xml.etree.ElementTree as ET

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO_ROOT, "tools"))

import generate_test_events  # noqa: E402

RULES_PATH = os.path.join(
    REPO_ROOT, "wazuh", "rules", "0910-sophos_central_rules.xml"
)

BASE_RULE = 100200


def osregex_to_python(pattern):
    """Translate the osregex subset used in the ruleset to a Python regex.

    osregex is not PCRE. `\\.` means "any character" and a bare `.` is a
    literal dot, which is the reverse of PCRE and the single easiest way to
    write a rule that silently never matches.
    """
    out = []
    i = 0
    while i < len(pattern):
        if pattern[i] == "\\" and i + 1 < len(pattern) and pattern[i + 1] == ".":
            out.append(".")  # osregex \. == any character
            i += 2
        elif pattern[i] == ".":
            out.append("\\.")  # osregex bare . == literal dot
            i += 1
        else:
            out.append(pattern[i])
            i += 1
    return "".join(out)


def load_child_rules():
    """Rules chained off the base rule, in file order.
    Returns:
        list -- [(rule_id, level, {field: compiled_regex})]
    """
    root = ET.parse(RULES_PATH).getroot()
    rules = []
    for rule in root.iter("rule"):
        parents = [p.text.strip() for p in rule.findall("if_sid") if p.text]
        if not parents:
            continue
        fields = {}
        for field in rule.findall("field"):
            fields[field.get("name")] = re.compile(osregex_to_python(field.text))
        rules.append(
            (int(rule.get("id")), int(rule.get("level")), parents[0], fields)
        )
    return rules


def first_matching_rule(event, rules):
    """Walk the rule list the way Wazuh walks siblings: first match wins.
    Arguments:
        event {dict}: a shaped event
        rules {list}: output of load_child_rules
    Returns:
        int or None -- id of the matching rule
    """
    matched = str(BASE_RULE)
    result = None
    # Two passes so a rule chained off another child (100241 off 100240) is
    # reachable after its parent matches.
    for _ in range(2):
        for rule_id, _level, parent, fields in rules:
            if parent != matched:
                continue
            if all(
                name in event and pattern.search(str(event[name]))
                for name, pattern in fields.items()
            ):
                result = rule_id
                matched = str(rule_id)
                break
        else:
            break
    return result


class TestOsregexTranslation(unittest.TestCase):
    def test_escaped_dot_is_wildcard(self):
        # osregex \.* is the wildcard, equivalent to PCRE .*
        rx = re.compile(osregex_to_python(r"Threat::\.*CleanupFailed$"))
        self.assertTrue(rx.search("Event::Endpoint::Threat::PuaCleanupFailed"))
        self.assertTrue(rx.search("Event::Endpoint::Threat::CleanupFailed"))
        self.assertTrue(rx.search("Event::Endpoint::Threat::HIPSCleanupFailed"))

    def test_bare_dot_is_literal(self):
        rx = re.compile(osregex_to_python("a.b"))
        self.assertTrue(rx.search("a.b"))
        self.assertIsNone(rx.search("axb"))


class TestGeneratedEventsMatchRules(unittest.TestCase):
    def setUp(self):
        self.rules = load_child_rules()

    def test_every_generated_event_matches_its_expected_rule(self):
        count = len(generate_test_events.SCENARIOS)
        events = list(generate_test_events.generate(count, spacing_seconds=5))
        self.assertEqual(len(events), count)

        import json

        for i, (line, _expect) in enumerate(events):
            event = json.loads(line)
            expected = generate_test_events.SCENARIOS[i]["expect_rule"]
            actual = first_matching_rule(event, self.rules)
            self.assertEqual(
                actual,
                expected,
                "event %s (%s) matched rule %s, expected %s"
                % (i + 1, event["type"], actual, expected),
            )

    def test_cleanup_failure_outranks_plain_detection(self):
        # 100212 must be evaluated before the severity fallback, otherwise a
        # cleanup failure alerts at the wrong level.
        ids = [r[0] for r in self.rules]
        self.assertLess(ids.index(100212), ids.index(100203))

    def test_specific_rules_precede_severity_fallback(self):
        ids = [r[0] for r in self.rules]
        fallback = min(ids.index(100201), ids.index(100202), ids.index(100203))
        for specific in (100210, 100212, 100213, 100214, 100220, 100230):
            self.assertLess(
                ids.index(specific),
                fallback,
                "rule %s is shadowed by the severity fallback" % specific,
            )

    def test_unmatched_type_falls_back_to_severity(self):
        import json

        event = json.loads(
            json.dumps(
                {
                    "integration": "sophos-central",
                    "type": "Event::Endpoint::SomethingNew",
                    "severity": "medium",
                    "datastream": "event",
                    "location": "TEST-WKS-99",
                }
            )
        )
        self.assertEqual(first_matching_rule(event, self.rules), 100202)


class TestSampleFileMatchesRules(unittest.TestCase):
    def test_shipped_samples_all_match_something(self):
        import json

        rules = load_child_rules()
        path = os.path.join(REPO_ROOT, "wazuh", "samples", "sample_events.jsonl")
        with open(path) as f:
            for lineno, line in enumerate(f, 1):
                if not line.strip():
                    continue
                event = json.loads(line)
                self.assertIsNotNone(
                    first_matching_rule(event, rules),
                    "sample line %s matches no rule" % lineno,
                )


if __name__ == "__main__":
    unittest.main()
