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
"""Offline approximation of Wazuh's rule matching.

Models the two things that break silently when the ruleset is edited - sibling
evaluation order, and osregex field patterns. It knows nothing about frequency,
timeframe, same_field or if_matched_sid, so correlation rules are invisible to
it. wazuh-logtest on a real manager remains the authority.

Shared by tools/audit_coverage.py and the unit tests so that both agree on what
"which rule matches this event" means.
"""

import os
import re
import xml.etree.ElementTree as ET

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_DIR = os.path.join(REPO_ROOT, "wazuh", "rules")
DEFAULT_RULES = os.path.join(RULES_DIR, "0910-sophos_central_rules.xml")

BASE_RULE = 100200

# Rules that exist only to catch anything the specific rules missed. An event
# landing here is not necessarily wrong, but it means the ruleset has nothing
# to say about that event type beyond the severity Sophos assigned it.
FALLBACK_RULES = {100201, 100202, 100203}


def osregex_to_python(pattern):
    """Translate the osregex subset used in the ruleset to a Python regex.

    osregex is not PCRE. `\\.` means "any character" and a bare `.` is a
    literal dot, the reverse of PCRE, and the easiest way to write a rule that
    silently never matches.
    """
    out = []
    i = 0
    while i < len(pattern):
        if pattern[i] == "\\" and i + 1 < len(pattern) and pattern[i + 1] == ".":
            out.append(".")
            i += 2
        elif pattern[i] == ".":
            out.append("\\.")
            i += 1
        else:
            out.append(pattern[i])
            i += 1
    return "".join(out)


def load_child_rules(path=None):
    """Rules chained off a parent, in file order.
    Returns:
        list -- [(rule_id, level, parent_id, {field: compiled_regex})]
    """
    root = ET.parse(path or DEFAULT_RULES).getroot()
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


def load_descriptions(path=None):
    """Rule id to description text."""
    root = ET.parse(path or DEFAULT_RULES).getroot()
    return {
        int(r.get("id")): (r.findtext("description") or "") for r in root.iter("rule")
    }


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
    # Two passes so a rule chained off another child is reachable once its
    # parent has matched.
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
