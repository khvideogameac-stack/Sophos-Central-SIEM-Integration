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
"""Tests for the wazuh output format."""

import json
import unittest

import siem

from mock import MagicMock
from mock import patch


def sophos_event(**overrides):
    """A representative Sophos Central event."""
    event = {
        "severity": "high",
        "location": "WIN-DESKTOP-01",
        "endpoint_type": "computer",
        "source_info": {"ip": "203.0.113.45"},
        "type": "Event::Endpoint::Threat::Detected",
        "id": "evt-0001",
        "datastream": "event",
        "when": "2026-07-25T10:00:00.000Z",
        "source": "jdoe@example.com",
        "name": "EICAR-AV-Test",
    }
    event.update(overrides)
    return event


class TestResolveDotted(unittest.TestCase):
    def test_resolves_nested_path(self):
        data = {"a": {"b": {"c": 1}}}
        self.assertEqual(siem.resolve_dotted(data, "a.b.c"), 1)

    def test_missing_segment_returns_none(self):
        data = {"a": {"b": {}}}
        self.assertIsNone(siem.resolve_dotted(data, "a.b.c"))
        self.assertIsNone(siem.resolve_dotted(data, "nope"))

    def test_scalar_midway_returns_none(self):
        # source_info arriving as a string rather than an object must not raise.
        self.assertIsNone(siem.resolve_dotted({"a": "scalar"}, "a.b"))


class TestPromoteWazuhFields(unittest.TestCase):
    def test_promotes_srcip_for_geoip(self):
        out = siem.promote_wazuh_fields(sophos_event())
        self.assertEqual(out["srcip"], "203.0.113.45")

    def test_promotes_source_to_dstuser(self):
        out = siem.promote_wazuh_fields(sophos_event())
        self.assertEqual(out["dstuser"], "jdoe@example.com")

    def test_keeps_original_field_paths(self):
        # Promotion copies rather than moves, so rules already written against
        # data.source_info.ip keep working.
        out = siem.promote_wazuh_fields(sophos_event())
        self.assertEqual(out["source_info"], {"ip": "203.0.113.45"})
        self.assertEqual(out["source"], "jdoe@example.com")

    def test_adds_integration_marker(self):
        out = siem.promote_wazuh_fields(sophos_event())
        self.assertEqual(out["integration"], "sophos-central")

    def test_adds_numeric_severity(self):
        for severity, expected in [
            ("none", 0),
            ("low", 1),
            ("medium", 5),
            ("high", 8),
            ("very_high", 10),
        ]:
            out = siem.promote_wazuh_fields(sophos_event(severity=severity))
            self.assertEqual(out["severity_num"], expected, severity)

    def test_unknown_severity_falls_back_to_zero(self):
        out = siem.promote_wazuh_fields(sophos_event(severity="bogus"))
        self.assertEqual(out["severity_num"], 0)

    def test_missing_severity_omits_severity_num(self):
        event = sophos_event()
        del event["severity"]
        out = siem.promote_wazuh_fields(event)
        self.assertNotIn("severity_num", out)

    def test_moves_aside_colliding_object(self):
        # Alert payloads can carry a top-level "data" object, which collides
        # with a Wazuh static field that expects a scalar.
        out = siem.promote_wazuh_fields(sophos_event(data={"rule": "PII"}))
        self.assertEqual(out["sophos_data"], {"rule": "PII"})
        self.assertNotIn("data", out)

    def test_moves_aside_colliding_list(self):
        out = siem.promote_wazuh_fields(sophos_event(action=["a", "b"]))
        self.assertEqual(out["sophos_action"], ["a", "b"])
        self.assertNotIn("action", out)

    def test_keeps_scalar_reserved_keys_in_place(self):
        # A scalar in a reserved slot is exactly what Wazuh wants, leave it.
        out = siem.promote_wazuh_fields(sophos_event(status="active"))
        self.assertEqual(out["status"], "active")
        self.assertEqual(out["id"], "evt-0001")
        self.assertNotIn("sophos_status", out)

    def test_missing_source_info_is_not_fatal(self):
        event = sophos_event()
        del event["source_info"]
        out = siem.promote_wazuh_fields(event)
        self.assertNotIn("srcip", out)

    def test_does_not_clobber_existing_promoted_value(self):
        out = siem.promote_wazuh_fields(sophos_event(srcip="10.0.0.1"))
        self.assertEqual(out["srcip"], "10.0.0.1")

    def test_non_scalar_source_is_not_promoted(self):
        out = siem.promote_wazuh_fields(sophos_event(source={"weird": True}))
        self.assertNotIn("dstuser", out)

    def test_output_is_json_serialisable(self):
        # The whole point is one JSON object per line for logcollector.
        out = siem.promote_wazuh_fields(sophos_event())
        line = json.dumps(out, ensure_ascii=False)
        self.assertNotIn("\n", line)
        self.assertEqual(json.loads(line)["srcip"], "203.0.113.45")


class TestWriteWazuhFormat(unittest.TestCase):
    def setUp(self):
        self.LOGGER_MOCK = MagicMock()
        siem.SIEM_LOGGER = self.LOGGER_MOCK

    @patch("name_mapping.update_fields")
    def test_writes_one_line_per_event(self, mock_update_fields):
        siem.write_wazuh_format([sophos_event(), sophos_event()], MagicMock())
        self.assertEqual(self.LOGGER_MOCK.info.call_count, 2)

    @patch("name_mapping.update_fields")
    def test_drops_null_values(self, mock_update_fields):
        # Nulls carry no information and just widen the index mapping.
        siem.write_wazuh_format([sophos_event(origin=None)], MagicMock())
        written = json.loads(self.LOGGER_MOCK.info.call_args[0][0])
        self.assertNotIn("origin", written)

    @patch("name_mapping.update_fields")
    def test_written_line_carries_promoted_fields(self, mock_update_fields):
        siem.write_wazuh_format([sophos_event()], MagicMock())
        written = json.loads(self.LOGGER_MOCK.info.call_args[0][0])
        self.assertEqual(written["srcip"], "203.0.113.45")
        self.assertEqual(written["integration"], "sophos-central")


if __name__ == "__main__":
    unittest.main()
