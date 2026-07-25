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

import unittest
import shutil
import tempfile
import os
import config


class TestConfig(unittest.TestCase):
    """Test Config file items are exposed as attributes on config object"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="config_test", dir=".")

    def tearDown(self):
        if os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir)

    def write_config(self, text):
        cfg_path = os.path.join(self.tmpdir, "config.ini")
        with open(cfg_path, "wb") as fp:
            fp.write(text.encode("utf-8"))
        return cfg_path

    def testReadingWhenAttributeExists(self):
        cfg = config.Config(self.write_config("[login]\ntoken_info = MY_TOKEN\n"))
        self.assertEqual(cfg.token_info, "MY_TOKEN")

    def testMissingFileIsAnError(self):
        # ConfigParser.read() ignores a missing file. Combined with the
        # defaults that yields a healthy looking run writing to the wrong file
        # in the wrong format, so it has to fail loudly instead.
        with self.assertRaises(IOError) as ctx:
            config.Config(os.path.join(self.tmpdir, "does_not_exist.ini"))
        self.assertIn("Config file not found", str(ctx.exception))

    def testMissingLoginSectionIsAnError(self):
        with self.assertRaises(ValueError) as ctx:
            config.Config(self.write_config("filename = result.txt\n"))
        self.assertIn("[login]", str(ctx.exception))

    def testWrongSectionNameIsAnError(self):
        with self.assertRaises(ValueError):
            config.Config(self.write_config("[sophos]\nfilename = x.json\n"))

    def testFileValueWinsOverDefault(self):
        cfg = config.Config(
            self.write_config("[login]\nfilename = sophos_central.json\n")
        )
        self.assertEqual(cfg.filename, "sophos_central.json")

    def testDefaultAppliesWhenOptionAbsent(self):
        # An older config.ini must survive an upgrade that adds new options.
        cfg = config.Config(self.write_config("[login]\nfilename = x.json\n"))
        self.assertEqual(cfg.request_timeout_seconds, "30")

    def testEnvironmentOverridesFile(self):
        cfg = config.Config(self.write_config("[login]\nclient_id = from_file\n"))
        self.assertEqual(cfg.client_id, "from_file")
        os.environ["SOPHOS_CLIENT_ID"] = "from_env"
        try:
            self.assertEqual(cfg.client_id, "from_env")
        finally:
            del os.environ["SOPHOS_CLIENT_ID"]


class TestToken(unittest.TestCase):
    """Test the token gets parsed"""

    def testParse(self):
        txt = "url: https://anywhere.com/api, x-api-key: random, Authorization: Basic KJNKLJNjklNLKHB= "
        t = config.Token(txt)
        self.assertEqual(t.url, "https://anywhere.com/api")
        self.assertEqual(t.api_key, "random")
        self.assertEqual(t.authorization, "Basic KJNKLJNjklNLKHB=")
