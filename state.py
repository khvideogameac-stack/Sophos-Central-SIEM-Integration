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
import sys
import os
import errno
import json
import tempfile
from pathlib import Path
import logging
import exit_codes

try:
    import fcntl
except ImportError:  # Windows
    fcntl = None


class LockUnavailable(Exception):
    """The lock file itself could not be opened.

    Distinct from the lock being held: this is a permissions or path problem
    that no amount of waiting will fix.
    """


class RunLock:
    """An advisory lock ensuring only one collector runs against a state file.

    Overlapping runs - a slow run still paginating when cron starts the next
    one - race on the cursor, which duplicates events downstream and can move
    the cursor backwards. Held for the lifetime of the process; the lock is
    released by the OS if we are killed.

    The lock file is deliberately persistent. Unlinking it after releasing the
    flock creates a race where another process can lock the old inode while a
    third process creates and locks a new file at the same pathname.
    """

    def __init__(self, lock_file):
        self.lock_file = lock_file
        self.handle = None

    def acquire(self):
        """Take the lock.
        Returns:
            bool -- True if acquired, False if another run genuinely holds it
        Raises:
            LockUnavailable -- the lock file could not be opened at all
        """
        if fcntl is None:
            logging.debug("File locking unavailable on this platform, skipping run lock")
            return True

        try:
            self.handle = open(self.lock_file, "a")
        except OSError as e:
            raise LockUnavailable(
                "Cannot open lock file %s: %s. Check that the state directory "
                "is writable by the user running the collector."
                % (self.lock_file, e)
            )

        try:
            fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as e:
            self.handle.close()
            self.handle = None
            if e.errno in (errno.EACCES, errno.EAGAIN):
                return False
            raise LockUnavailable(
                "Cannot lock %s: %s" % (self.lock_file, e)
            )

        try:
            self.handle.seek(0)
            self.handle.truncate()
            self.handle.write(str(os.getpid()))
            self.handle.flush()
        except OSError:
            pass
        return True

    def release(self):
        """Release the advisory lock while leaving the lock file in place."""
        if self.handle is None:
            return
        try:
            fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
        except (IOError, OSError):
            pass
        finally:
            try:
                self.handle.close()
            except (IOError, OSError):
                pass
            self.handle = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.release()
        return False


class State:
    def __init__(self, options, state_file):
        """Class create state file and providing state file data"""

        if state_file and Path(state_file).suffix != ".json":
            raise SystemExit(
                "Sophos state file is not in valid format. it's must be with a .json extension"
            )
        self.options = options
        if "SOPHOS_SIEM_HOME" in os.environ:
            app_path = os.environ["SOPHOS_SIEM_HOME"]
        else:
            app_path = os.path.join(os.getcwd())

        self.state_file = self.get_state_file(app_path, state_file)
        self.create_state_dir(self.state_file)
        self.state_data = self.load_state_file()

    def get_lock_file(self):
        """Path of the run lock guarding this state file
        Returns:
            string -- lock file path
        """
        return self.state_file + ".lock"

    def create_state_dir(self, state_file):
        """Create state directory
        Arguments:
            state_file {string}: state file path
        """
        state_dir = os.path.dirname(state_file)
        if not os.path.exists(state_dir):
            try:
                os.makedirs(state_dir)
            except OSError as e:
                logging.critical("Failed to create %s, %s" % (state_dir, str(e)))
                raise SystemExit(exit_codes.STATE_ERROR)

    def get_state_file(self, app_path, state_file):
        """Return state cache file path
        Arguments:
            app_path {string}: application path
            state_file {string}: state file path
        Returns:
            dict -- state file path
        """
        if not state_file:
            return os.path.join(app_path, "state", "siem_sophos.json")
        else:
            return (
                state_file
                if os.path.isabs(state_file)
                else os.path.join(app_path, state_file)
            )

    def load_state_file(self):
        """Get state file data
        Returns:
            dict -- Return state file data or exit if found any error
        """
        try:
            with open(self.state_file, "rb") as f:
                return json.load(f)
        except IOError:
            logging.info(f"Sophos state file not found; Reinitialize Communication; state file={self.state_file} ")
        except json.decoder.JSONDecodeError:
            logging.critical(
                "Sophos state file %s is not valid JSON. Move it aside to restart "
                "collection, note this re-fetches the last 12 hours and will "
                "duplicate events downstream." % self.state_file
            )
            raise SystemExit(exit_codes.STATE_ERROR)
        return {}

    def save_state(self, state_data_key, state_data_value):
        """save data in state file. Data store in nested object by splitting key with `.` separator
        Arguments:
            state_data_key {string}: state key
            state_data_value {string}: state value
        """
        key_arr = state_data_key.split(".")
        sub_data = self.state_data
        for item in key_arr[0:-1]:
            if item not in sub_data.keys():
                sub_data[item] = {}
            sub_data = sub_data[item]
        sub_data[key_arr[-1]] = state_data_value

        self.write_state_file(json.dumps(self.state_data, indent=4))

    def write_state_file(self, data):
        """Write data in state file, atomically.
        Writing in place truncates the file first, so a crash mid-write leaves a
        corrupt state file that the next run refuses to load. Writing to a
        temporary file in the same directory and renaming makes the replacement
        atomic: the state file is always either the old content or the new.
        Arguments:
            data {dict}: state data object
        """
        state_dir = os.path.dirname(self.state_file) or "."
        tmp_fd, tmp_path = tempfile.mkstemp(
            dir=state_dir, prefix=".siem_state_", suffix=".tmp"
        )
        try:
            with os.fdopen(tmp_fd, "w") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, self.state_file)
        except Exception as e:
            logging.error("Failed to write state file %s: %s" % (self.state_file, e))
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
