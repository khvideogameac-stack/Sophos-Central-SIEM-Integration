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
"""Static checks on the shipped Wazuh rules.

Catches the mistakes that only show up as a manager that refuses to start:
malformed XML, duplicate or out-of-range rule ids, children pointing at a
parent that is not defined, and levels outside 0-16. It cannot tell you whether
a rule matches - run wazuh-logtest for that.

Run from the repository root:  python tools/validate_wazuh_rules.py
"""

import glob
import json
import os
import sys
import xml.etree.ElementTree as ET

# Wazuh reserves everything below 100000 for its own ruleset.
MIN_CUSTOM_RULE_ID = 100000
MAX_RULE_LEVEL = 16

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def fail(errors, message):
    errors.append(message)
    print("FAIL: %s" % message)


def validate_xml_parses(paths, errors):
    """Every shipped XML file must be well formed."""
    trees = {}
    for path in paths:
        try:
            trees[path] = ET.parse(path)
            print("ok   parsed %s" % os.path.relpath(path, REPO_ROOT))
        except ET.ParseError as e:
            # A stray '--' inside an XML comment is the usual culprit.
            fail(errors, "%s is not well-formed XML: %s" % (path, e))
    return trees


def validate_rules(tree, path, errors):
    """Check ids, levels and if_sid references in a rule file."""
    root = tree.getroot()
    rules = list(root.iter("rule"))
    if not rules:
        return

    ids = []
    for rule in rules:
        rule_id = rule.get("id")
        if rule_id is None or not rule_id.isdigit():
            fail(errors, "%s: rule with missing or non-numeric id %r" % (path, rule_id))
            continue
        rule_id = int(rule_id)
        ids.append(rule_id)

        if rule_id < MIN_CUSTOM_RULE_ID:
            fail(
                errors,
                "%s: rule %s is below %s, which Wazuh reserves for its own ruleset"
                % (path, rule_id, MIN_CUSTOM_RULE_ID),
            )

        level = rule.get("level")
        if level is None or not level.isdigit() or int(level) > MAX_RULE_LEVEL:
            fail(errors, "%s: rule %s has invalid level %r" % (path, rule_id, level))

    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    if duplicates:
        fail(errors, "%s: duplicate rule ids %s" % (path, duplicates))

    # Every chained rule must reference a parent that exists in this file,
    # otherwise the rule silently never fires.
    defined = set(ids)
    for rule in rules:
        for tag in ("if_sid", "if_matched_sid"):
            for ref in rule.findall(tag):
                if ref.text and int(ref.text.strip()) not in defined:
                    fail(
                        errors,
                        "%s: rule %s references unknown %s %s"
                        % (path, rule.get("id"), tag, ref.text.strip()),
                    )

    print("ok   %s rules, ids %s-%s" % (len(ids), min(ids), max(ids)))


def validate_samples(path, errors):
    """Sample events must be one valid JSON object per line."""
    if not os.path.exists(path):
        return
    with open(path) as f:
        for lineno, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as e:
                fail(errors, "%s line %s is not valid JSON: %s" % (path, lineno, e))
                continue
            # The base rule keys on this, so a sample without it tests nothing.
            if event.get("integration") != "sophos-central":
                fail(
                    errors,
                    "%s line %s is missing integration=sophos-central" % (path, lineno),
                )
    print("ok   samples in %s" % os.path.relpath(path, REPO_ROOT))


def main():
    errors = []
    xml_paths = sorted(
        glob.glob(os.path.join(REPO_ROOT, "wazuh", "**", "*.xml"), recursive=True)
    )
    if not xml_paths:
        fail(errors, "no XML files found under wazuh/")

    trees = validate_xml_parses(xml_paths, errors)
    for path, tree in trees.items():
        if os.sep + "rules" + os.sep in path:
            validate_rules(tree, path, errors)

    validate_samples(
        os.path.join(REPO_ROOT, "wazuh", "samples", "sample_events.jsonl"), errors
    )

    if errors:
        print("\n%s problem(s) found" % len(errors))
        return 1
    print("\nall Wazuh rule checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
