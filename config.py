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

import os
import re
import configparser as ConfigParser


# Defaults for every option the code reads. Without these, a config.ini written
# for an earlier release raises NoOptionError the first time a newly added
# option is read, so upgrading the code breaks a working deployment.
CONFIG_DEFAULTS = {
    "token_info": "",
    "client_id": "",
    "client_secret": "",
    "tenant_id": "",
    "auth_url": "https://id.sophos.com/api/v2/oauth2/token",
    "api_host": "api.central.sophos.com",
    "format": "json",
    "filename": "result.txt",
    "endpoint": "event",
    "address": "/var/run/syslog",
    "facility": "daemon",
    "socktype": "udp",
    "append_nul": "false",
    "state_file_path": "state/siem_sophos.json",
    "events_from_date_offset_minutes": "0",
    "alerts_from_date_offset_minutes": "0",
    "convert_dhost_field_to_valid_fqdn": "true",
    "logging_level": "INFO",
    "request_timeout_seconds": "30",
    "max_log_file_size_mb": "0",
    "log_file_backup_count": "5",
}

# Options that may be supplied through the environment instead of config.ini, so
# that secrets can come from a systemd credential, a Docker secret or a
# Kubernetes secret rather than a file on disk. The environment wins.
ENV_OVERRIDES = {
    "client_id": "SOPHOS_CLIENT_ID",
    "client_secret": "SOPHOS_CLIENT_SECRET",
    "tenant_id": "SOPHOS_TENANT_ID",
    "token_info": "SOPHOS_TOKEN_INFO",
}


class Config:
    """Class providing config values"""

    def __init__(self, path):
        """Open the config file"""
        # ConfigParser.read() silently ignores a file that does not exist.
        # Combined with the defaults below that produces a run which looks
        # entirely healthy while writing to the wrong file in the wrong format,
        # so check for the file rather than letting it pass.
        if not os.path.isfile(path):
            raise IOError(
                "Config file not found: %s. Copy config.ini.sample to "
                "config.ini, or pass an explicit path with -c." % path
            )

        # Probe without defaults first. Defaults appear in every section, so
        # once they are applied there is no way to tell whether the file itself
        # supplied [login] - and a file lacking it would answer every lookup
        # from the defaults without complaint.
        probe = ConfigParser.ConfigParser()
        try:
            probe.read(path)
        except ConfigParser.MissingSectionHeaderError:
            # No header at all. Same operator error as a misnamed section, so
            # give it the same message rather than a parser traceback.
            probe = None
        if probe is None or not probe.has_section("login"):
            raise ValueError(
                "Config file %s has no [login] section. Every option must sit "
                "under a line reading exactly [login]." % path
            )

        self.config = ConfigParser.ConfigParser(defaults=CONFIG_DEFAULTS)
        self.config.read(path)
        self.path = path

    def __getattr__(self, name):
        # __getattr__ runs only when normal lookup fails, so guard against
        # recursing if it is reached before __init__ assigned self.config.
        if name == "config":
            raise AttributeError(name)
        env_var = ENV_OVERRIDES.get(name)
        if env_var and os.environ.get(env_var):
            return os.environ[env_var]
        return self.config.get("login", name)


class Token:
    def __init__(self, token_txt):
        """Initialize with the token text"""
        rex_txt = r"url\: (?P<url>https\://.+), x-api-key\: (?P<api_key>.+), Authorization\: (?P<authorization>.+)$"
        rex = re.compile(rex_txt)
        m = rex.search(token_txt)
        if m is None:
            raise ValueError(
                "token_info in config.ini is empty or malformed. Set client_id and "
                "client_secret, or paste the full 'API Access URL + Headers' block "
                "from Sophos Central into token_info."
            )
        self.url = m.group("url")
        self.api_key = m.group("api_key")
        self.authorization = m.group("authorization").strip()
