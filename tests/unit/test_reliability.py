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
"""Regression tests for the failure paths an unattended collector depends on."""

import json
import os
import shutil
import tempfile
import unittest
import urllib.error as urlerror

import api_client
import exit_codes
import state

from mock import MagicMock
from mock import patch


class Options:
    def __init__(self):
        self.quiet = False
        self.debug = False
        self.light = False
        self.since = False


class Config:
    def __init__(self):
        self.filename = "stdout"
        self.facility = "daemon"
        self.address = "localhost:514"
        self.socktype = "udp"
        self.format = "json"
        self.client_id = ""
        self.client_secret = ""
        self.tenant_id = ""
        self.token_info = ""
        self.auth_url = ""
        self.api_host = ""
        self.append_nul = False
        self.events_from_date_offset_minutes = 0
        self.alerts_from_date_offset_minutes = 0


class FakeState:
    def __init__(self):
        self.state_data = {}


def build_client():
    api_client.urlrequest.HTTPSHandler = MagicMock()
    api_client.urlrequest.build_opener = MagicMock()
    return api_client.ApiClient("/siem/v1/events", Options(), Config(), FakeState())


class TestRequestRetry(unittest.TestCase):
    """The retry loop used to fall off the end and return None, which surfaced
    as a TypeError in json.loads several frames away."""

    def setUp(self):
        self.client = build_client()

    def http_error(self, code):
        return urlerror.HTTPError("http://x", code, "err", {}, None)

    @patch("api_client.time.sleep")
    def test_raises_rather_than_returning_none_when_retries_exhausted(self, _sleep):
        self.client.opener.open = MagicMock(side_effect=self.http_error(503))
        with self.assertRaises(api_client.SophosApiError):
            self.client.request_url("http://x", None, {}, retry_count=3)

    @patch("api_client.time.sleep")
    def test_retries_exactly_retry_count_times(self, _sleep):
        self.client.opener.open = MagicMock(side_effect=self.http_error(429))
        with self.assertRaises(api_client.SophosApiError):
            self.client.request_url("http://x", None, {}, retry_count=4)
        self.assertEqual(self.client.opener.open.call_count, 4)

    @patch("api_client.time.sleep")
    def test_retries_connection_errors(self, _sleep):
        # URLError, not HTTPError: DNS failure, refused connection, TLS timeout.
        # These were previously not caught at all and killed the run.
        self.client.opener.open = MagicMock(side_effect=urlerror.URLError("no dns"))
        with self.assertRaises(api_client.SophosApiError):
            self.client.request_url("http://x", None, {}, retry_count=2)
        self.assertEqual(self.client.opener.open.call_count, 2)

    @patch("api_client.time.sleep")
    def test_succeeds_after_transient_failure(self, _sleep):
        good = MagicMock()
        good.read.return_value = b'{"ok": true}'
        self.client.opener.open = MagicMock(
            side_effect=[self.http_error(503), good]
        )
        result = self.client.request_url("http://x", None, {}, retry_count=3)
        self.assertEqual(result, b'{"ok": true}')

    def test_does_not_retry_client_errors(self):
        # A 400 will fail identically every time, retrying just delays the error.
        err = self.http_error(400)
        err.read = MagicMock(return_value=b"bad request")
        self.client.opener.open = MagicMock(side_effect=err)
        with self.assertRaises(urlerror.HTTPError):
            self.client.request_url("http://x", None, {}, retry_count=3)
        self.assertEqual(self.client.opener.open.call_count, 1)

    def test_backoff_grows_and_is_capped(self):
        delays = [self.client.retry_delay(i) for i in range(0, 10)]
        self.assertLess(delays[0], delays[3])
        self.assertLessEqual(max(delays), api_client.RETRY_MAX_DELAY_SECONDS)

    def test_honours_retry_after_header(self):
        self.assertEqual(self.client.retry_delay(0, retry_after="7"), 7)

    def test_ignores_unparsable_retry_after(self):
        # Retry-After may be an HTTP date, which we do not parse; fall back.
        delay = self.client.retry_delay(0, retry_after="Wed, 21 Oct 2026 07:28:00 GMT")
        self.assertGreater(delay, 0)


class TestResponseValidation(unittest.TestCase):
    """A malformed page response used to raise a bare KeyError on next_cursor."""

    def setUp(self):
        self.client = build_client()

    def test_rejects_response_missing_pagination_keys(self):
        with self.assertRaises(api_client.SophosApiError) as ctx:
            self.client.validate_response({"items": []}, "events")
        self.assertIn("has_more", str(ctx.exception))

    def test_rejects_non_object_response(self):
        with self.assertRaises(api_client.SophosApiError):
            self.client.validate_response([], "events")

    def test_surfaces_api_error_message(self):
        with self.assertRaises(api_client.SophosApiError) as ctx:
            self.client.validate_response({"message": "quota exceeded"}, "events")
        self.assertIn("quota exceeded", str(ctx.exception))

    def test_accepts_valid_response(self):
        self.client.validate_response(
            {"has_more": False, "next_cursor": "abc", "items": []}, "events"
        )


class TestIntConfig(unittest.TestCase):
    """Missing options must not break an upgrade from an older config.ini."""

    def setUp(self):
        self.client = build_client()

    def test_missing_option_falls_back_to_default(self):
        self.assertEqual(self.client.get_int_config("not_set_anywhere", 42), 42)

    def test_unparsable_option_falls_back_to_default(self):
        self.client.config.request_timeout_seconds = "banana"
        self.assertEqual(self.client.get_int_config("request_timeout_seconds", 30), 30)

    def test_reads_valid_option(self):
        self.client.config.request_timeout_seconds = "90"
        self.assertEqual(self.client.get_int_config("request_timeout_seconds", 30), 90)


class TestAtomicStateWrite(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="state_test")
        self.state = state.State(Options(), os.path.join(self.tmpdir, "s.json"))

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_write_is_readable(self):
        self.state.save_state("tenants.t1.cursor", "abc")
        with open(self.state.state_file) as f:
            self.assertEqual(json.load(f)["tenants"]["t1"]["cursor"], "abc")

    def test_leaves_no_temporary_files_behind(self):
        self.state.save_state("tenants.t1.cursor", "abc")
        leftovers = [f for f in os.listdir(self.tmpdir) if f.endswith(".tmp")]
        self.assertEqual(leftovers, [])

    def test_previous_content_survives_a_failed_write(self):
        # The point of writing to a temp file and renaming: a failure part way
        # through must not leave a truncated state file behind.
        self.state.save_state("tenants.t1.cursor", "first")
        with patch("os.replace", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.state.save_state("tenants.t1.cursor", "second")
        with open(self.state.state_file) as f:
            self.assertEqual(json.load(f)["tenants"]["t1"]["cursor"], "first")

    def test_corrupt_state_file_exits_non_zero(self):
        with open(self.state.state_file, "w") as f:
            f.write("{ this is not json")
        with self.assertRaises(SystemExit) as ctx:
            self.state.load_state_file()
        self.assertEqual(ctx.exception.code, exit_codes.STATE_ERROR)
        self.assertNotEqual(ctx.exception.code, 0)


class TestRunLock(unittest.TestCase):
    """Overlapping cron runs race the cursor and duplicate events downstream."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="lock_test")
        self.lock_path = os.path.join(self.tmpdir, "s.json.lock")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_second_acquire_is_refused(self):
        first = state.RunLock(self.lock_path)
        self.assertTrue(first.acquire())
        second = state.RunLock(self.lock_path)
        self.assertFalse(second.acquire())
        first.release()

    def test_lock_is_reusable_after_release(self):
        first = state.RunLock(self.lock_path)
        self.assertTrue(first.acquire())
        first.release()
        second = state.RunLock(self.lock_path)
        self.assertTrue(second.acquire())
        second.release()

    def test_release_removes_lock_file(self):
        lock = state.RunLock(self.lock_path)
        lock.acquire()
        lock.release()
        self.assertFalse(os.path.exists(self.lock_path))

    def test_works_as_context_manager(self):
        with state.RunLock(self.lock_path) as lock:
            self.assertTrue(lock.acquire())
        self.assertFalse(os.path.exists(self.lock_path))


class TestExitCodes(unittest.TestCase):
    def test_all_failure_codes_are_non_zero(self):
        # A bare `raise SystemExit()` exits 0, which is what this guards against.
        for name in (
            "CONFIG_ERROR",
            "AUTH_ERROR",
            "TRANSPORT_ERROR",
            "STATE_ERROR",
            "ALREADY_RUNNING",
        ):
            self.assertNotEqual(getattr(exit_codes, name), 0, name)

    def test_codes_are_distinct(self):
        codes = [
            exit_codes.OK,
            exit_codes.CONFIG_ERROR,
            exit_codes.AUTH_ERROR,
            exit_codes.TRANSPORT_ERROR,
            exit_codes.STATE_ERROR,
            exit_codes.ALREADY_RUNNING,
        ]
        self.assertEqual(len(codes), len(set(codes)))


if __name__ == "__main__":
    unittest.main()
