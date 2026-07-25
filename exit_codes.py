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
"""Process exit codes.

Anything scheduling this collector - cron, systemd, a Wazuh command wodle - can
only tell success from failure by the exit code, so every abnormal termination
must use a non-zero one. Note that a bare ``raise SystemExit()`` exits with 0,
which is why these constants exist and are always passed explicitly.
"""

# Collection completed (this includes "no new events", which is not an error).
OK = 0

# config.ini is missing, unreadable, or holds an invalid value.
CONFIG_ERROR = 1

# Sophos Central rejected our credentials, or the tenant could not be resolved.
AUTH_ERROR = 2

# Could not reach a required endpoint: the Sophos API, or the syslog target.
TRANSPORT_ERROR = 3

# The state file is unusable and the operator has to intervene.
STATE_ERROR = 4

# Another instance of the collector holds the run lock.
ALREADY_RUNNING = 5
