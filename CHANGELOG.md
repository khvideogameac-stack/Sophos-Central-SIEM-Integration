# Unreleased (Wazuh integration)

Fork changes on top of upstream v2.1.0.

### Wazuh support

* New `format = wazuh` output, shaping events for Wazuh's JSON decoder: copies
  `source_info.ip` to `srcip` and `source` to `dstuser` so Wazuh promotes them
  to static fields (GeoIP, `<srcip>` and `<user>` matching), adds an
  `integration` marker and a numeric `severity_num`, and moves aside top-level
  keys that would collide with a Wazuh static field while carrying an object.
* Wazuh ruleset in `wazuh/rules/` (ids 100200-100292): threat detections, DLP,
  policy violations, the alert stream, and outbreak/worm correlation.
* `ossec.conf` snippet, sample events, and `tools/validate_wazuh_rules.py`.
* Setup guide in `docs/wazuh.md`.

### Reliability

* Failure paths now exit non-zero. A bare `raise SystemExit()` exits with 0, so
  a failed collection was indistinguishable from a successful one to cron or a
  Wazuh command wodle. Exit codes are defined in `exit_codes.py`.
* `request_url` no longer returns `None` after exhausting its retries, which
  surfaced as a `TypeError` in `json.loads` several frames away.
* Connection-level failures (DNS, refused connection, TLS timeout) are now
  retried. Previously only `HTTPError` was caught, so a network blip killed the
  run outright.
* Retries use exponential backoff with jitter and honour `Retry-After`.
* Page responses are validated before use, replacing a bare `KeyError` on
  `next_cursor` when the API returns an error body.
* State file writes are atomic, so a crash mid-write can no longer leave a
  truncated file that blocks every subsequent run.
* An advisory run lock prevents overlapping runs from racing the cursor.
* Configurable request timeout, so a hung connection cannot stall the schedule.

### Operations

* Optional output file rotation (`max_log_file_size_mb`), preventing unbounded
  growth of a file a log collector is tailing.
* Secrets can come from `SOPHOS_CLIENT_ID`, `SOPHOS_CLIENT_SECRET` and
  `SOPHOS_TENANT_ID`, which take precedence over `config.ini`.
* All config options now have defaults, so an older `config.ini` no longer
  breaks on upgrade.
* Sample config defaults to `logging_level = INFO`; `DEBUG` logs full API
  responses. Tenant API responses demoted from info to debug.
* `datetime.utcnow()` replaced ahead of its removal.

### Tests

* Fixed 10 tests that were failing on arrival against the current signatures.
* Added coverage for the wazuh format, retry behaviour, atomic state writes,
  the run lock, and exit codes.
* GitHub Actions running the suite on Python 3.9-3.13 plus rule validation.

# v2.1.0

This release contains the following fixes:

* Fix JSON output to emit one object per line [#52](https://github.com/sophos/Sophos-Central-SIEM-Integration/issues/52)
* Remove empty lines from JSON output [#37](https://github.com/sophos/Sophos-Central-SIEM-Integration/issues/37)
* Resolve issue seen with duplicate events [#50](https://github.com/sophos/Sophos-Central-SIEM-Integration/issues/50)
* Fix `dhost` in CEF output to make it valid [#18](https://github.com/sophos/Sophos-Central-SIEM-Integration/issues/18)

**Full Changelog**: https://github.com/sophos/Sophos-Central-SIEM-Integration/compare/v2.0.1...2.1

# v2.0.1

1. Added check for minimum supported Python version.

# v2.0.0

1. New JWT-based authentication for the SIEM API
- You can now use Sophos Central public [API credentials](https://developer.sophos.com/getting-started) to sync alerts and events from the SIEM API.
- Add `client_id` and `client_secret` to config.ini.
- API tokens are still supported but deprecated. This authentication mechanism will be removed in a future release.
2. Better support for partners and enterprise customers
- You can now use API credentials created from Partner Admin or Enterprise Admin in config.ini. You must identify the tenant from which to sync alerts and events by setting the `tenant_id` configuration parameter.
- When using tenant-level API credentials, `tenant_id` is optional as it is automatically determined from the API credentials.
3. State file consolidated
- We have added a new JSON state file to capture the last sync time for alerts and events. 
- Configure the path to the state file in config.ini.
4. Drop support for Python 2.x
- You now need Python 3.6+ to use this tool.

# v1.1.0

## New Features

1. ****Added a “datastream” text identifier to each object in the API output to distinguish between events and alerts****
- Example:
***_alert output_***

>{"rt": "2019-04-04T20:30:34.875Z", ***"datastream": "alert",*** "end": "2019-04-04T20:30:06.000Z", "severity": "medium", "name": "PsExec", "filePath": "C:\\Program Files (x86)\\Trojan Horse\\bin\\eicar.com", "data": {"source_info": {"ip": "10.1.39.32"}, "endpoint_id": "ac3f7176-ed20-4536-b54d-ab5c7ae2033d", "inserted_at": 1554409834852, "created_at": 1554409834852, "endpoint_type": "computer", "user_match_id": "5ca6696a1b1a2d0defa8b5dc", "endpoint_java_id": "ac3f7176-ed20-4536-b54d-ab5c7ae2033d", "threat_id": "5ca6696a1b1a2d0defa8b5da", "endpoint_platform": "windows", "event_service_id": "f1562f29-6f0a-4588-af4d-7ea5cb473262"}, "detection_identity_name": "PsExec", "threat_cleanable": false, "id": "f1562f29-6f0a-4588-af4d-7ea5cb473262", "dhost": "Lightning-lauat321ys", "threat": "PsExec", "suser": "Domain\\Lightning-zdko5xt0fh", "customer_id": "b87754e4-8a8b-4d12-8129-90f93529d81d", "type": "Event::Endpoint::Threat::PuaCleanupFailed", "event_service_event_id": "f1562f29-6f0a-4588-af4d-7ea5cb473262", "description": "Manual PUA cleanup required: 'PsExec' at 'C:\\Program Files (x86)\\Trojan Horse\\bin\\eicar.com'"}

- ***_event output_***
>{"threat": "PsExec", "duid": "5ca6696a1b1a2d0defa8b5db", "filePath": "C:\\Program Files (x86)\\Trojan Horse\\bin\\eicar.com", "detection_identity_name": "PsExec", "endpoint_type": "computer", "group": "PUA", "id": "f1562f29-6f0a-4588-af4d-7ea5cb473262", "name": "PsExec", "rt": "2019-04-04T20:30:34.852Z", "source_info": {"ip": "10.1.39.32"}, ***"datastream": "event",*** "end": "2019-04-04T20:30:06.000Z", "severity": "medium", "endpoint_id": "ac3f7176-ed20-4536-b54d-ab5c7ae2033d", "suser": "Domain\\Lightning-zdko5xt0fh", "customer_id": "b87754e4-8a8b-4d12-8129-90f93529d81d", "type": "Event::Endpoint::Threat::PuaCleanupFailed", "dhost": "Lightning-lauat321ys"}
2. ***Removed duplicate alert objects returned when requesting both events and alerts from SIEM API***
- See below for an example of 2 events from an event stream, and their corresponding alerts (matched by event_service_event_id) – exactly 1 alert per event.
- ***event output***
>{"threat": "PsExec", "duid": "5ca6696a1b1a2d0defa8b5db", "filePath": "C:\\Program Files (x86)\\Trojan Horse\\bin\\eicar.com", "detection_identity_name": "PsExec", "endpoint_type": "computer", "group": "PUA", ***"id": "f1562f29-6f0a-4588-af4d-7ea5cb473262"****, "name": "PsExec", "rt": "2019-04-04T20:30:34.852Z", "source_info": {"ip": "10.1.39.32"}, ***"datastream": "event"***, "end": "2019-04-04T20:30:06.000Z", "severity": "medium", "endpoint_id": "ac3f7176-ed20-4536-b54d-ab5c7ae2033d", "suser": "Domain\\Lightning-zdko5xt0fh", "customer_id": "b87754e4-8a8b-4d12-8129-90f93529d81d", "type": "Event::Endpoint::Threat::PuaCleanupFailed", "dhost": "Lightning-lauat321ys"}

>{"threat": "PsExec", "duid": "5ca6697d1b1a2d0defa8b5de", "filePath": "C:\\Program Files (x86)\\Trojan Horse\\bin\\eicar.com", "detection_identity_name": "PsExec", "endpoint_type": "computer", "group": "PUA", ***"id": "5f08e8de-19c4-4edf-9750-b872a93e3959"***, "name": "PsExec", "rt": "2019-04-04T20:30:53.352Z", "source_info": {"ip": "10.1.39.32"}, ***"datastream": "event"***, "end": "2019-04-04T20:30:24.000Z", "severity": "medium", "endpoint_id": "7f409f17-c22b-4961-ad14-7f05c6541c6f", "suser": "Domain\\Lightning-nz59n2u4tx", "customer_id": "b87754e4-8a8b-4d12-8129-90f93529d81d", "type": "Event::Endpoint::Threat::PuaCleanupFailed", "dhost": "Lightning-pn1a1apren"}

- ***alert output***
>{"rt": "2019-04-04T20:30:34.875Z", ***"datastream": "alert"***, "end": "2019-04-04T20:30:06.000Z", "severity": "medium", "name": "PsExec", "filePath": "C:\\Program Files (x86)\\Trojan Horse\\bin\\eicar.com", "data": {"source_info": {"ip": "10.1.39.32"}, "endpoint_id": "ac3f7176-ed20-4536-b54d-ab5c7ae2033d", "inserted_at": 1554409834852, "created_at": 1554409834852, "endpoint_type": "computer", "user_match_id": "5ca6696a1b1a2d0defa8b5dc", "endpoint_java_id": "ac3f7176-ed20-4536-b54d-ab5c7ae2033d", "threat_id": "5ca6696a1b1a2d0defa8b5da", "endpoint_platform": "windows", "event_service_id": "f1562f29-6f0a-4588-af4d-7ea5cb473262"}, "detection_identity_name": "PsExec", "threat_cleanable": false, "id": "f1562f29-6f0a-4588-af4d-7ea5cb473262", "dhost": "Lightning-lauat321ys", "threat": "PsExec", "suser": "Domain\\Lightning-zdko5xt0fh", "customer_id": "b87754e4-8a8b-4d12-8129-90f93529d81d", "type": "Event::Endpoint::Threat::PuaCleanupFailed", ***"event_service_event_id": "f1562f29-6f0a-4588-af4d-7ea5cb473262"***, "description": "Manual PUA cleanup required: 'PsExec' at 'C:\\Program Files (x86)\\Trojan Horse\\bin\\eicar.com'"}

>{"rt": "2019-04-04T20:30:53.381Z", ***"datastream": "alert"***, "end": "2019-04-04T20:30:24.000Z", "severity": "medium", "name": "PsExec", "filePath": "C:\\Program Files (x86)\\Trojan Horse\\bin\\eicar.com", "data": {"source_info": {"ip": "10.1.39.32"}, "endpoint_id": "7f409f17-c22b-4961-ad14-7f05c6541c6f", "inserted_at": 1554409853352, "created_at": 1554409853352, "endpoint_type": "computer", "user_match_id": "5ca6697d1b1a2d0defa8b5df", "endpoint_java_id": "7f409f17-c22b-4961-ad14-7f05c6541c6f", "threat_id": "5ca6697d1b1a2d0defa8b5dd", "endpoint_platform": "windows", "event_service_id": "5f08e8de-19c4-4edf-9750-b872a93e3959"}, "detection_identity_name": "PsExec", "threat_cleanable": false, "id": "5f08e8de-19c4-4edf-9750-b872a93e3959", "dhost": "Lightning-pn1a1apren", "threat": "PsExec", "suser": "Domain\\Lightning-nz59n2u4tx", "customer_id": "b87754e4-8a8b-4d12-8129-90f93529d81d", "type": "Event::Endpoint::Threat::PuaCleanupFailed", ***"event_service_event_id": "5f08e8de-19c4-4edf-9750-b872a93e3959"***, "description": "Manual PUA cleanup required: 'PsExec' at 'C:\\Program Files (x86)\\Trojan Horse\\bin\\eicar.com'"}

3. The following update is part of Central release 2019.15, and is live for ***all versions of SIEM client after release date 4/13/2019***
-	Updated conversion logic to ensure matching identifiers between output objects for the following elements:
--	endpoint_id
--	customer_id
--	event_service_event_id

- ***Event:***
>{"threat": "PsExec", "duid": "5ca6696a1b1a2d0defa8b5db", "filePath": "C:\\Program Files (x86)\\Trojan Horse\\bin\\eicar.com", "detection_identity_name": "PsExec", "endpoint_type": "computer", "group": "PUA", ***"id": "f1562f29-6f0a-4588-af4d-7ea5cb473262"***, "name": "PsExec", "rt": "2019-04-04T20:30:34.852Z", "source_info": {"ip": "10.1.39.32"}, ***"datastream": "event"***, "end": "2019-04-04T20:30:06.000Z", "severity": "medium", ***"endpoint_id": "ac3f7176-ed20-4536-b54d-ab5c7ae2033d"***, "suser": "Domain\\Lightning-zdko5xt0fh", ***"customer_id": "b87754e4-8a8b-4d12-8129-90f93529d81d"***, "type": "Event::Endpoint::Threat::PuaCleanupFailed", "dhost": "Lightning-lauat321ys"}

- ***Corresponding alert:***
>{"rt": "2019-04-04T20:30:34.875Z", ***"datastream": "alert"***, "end": "2019-04-04T20:30:06.000Z", "severity": "medium", "name": "PsExec", "filePath": "C:\\Program Files (x86)\\Trojan Horse\\bin\\eicar.com", "data": {"source_info": {"ip": "10.1.39.32"}, "endpoint_id": "ac3f7176-ed20-4536-b54d-ab5c7ae2033d", "inserted_at": 1554409834852, "created_at": 1554409834852, "endpoint_type": "computer", "user_match_id": "5ca6696a1b1a2d0defa8b5dc", "endpoint_java_id": "ac3f7176-ed20-4536-b54d-ab5c7ae2033d", "threat_id": "5ca6696a1b1a2d0defa8b5da", "endpoint_platform": "windows", ***"event_service_id": "f1562f29-6f0a-4588-af4d-7ea5cb473262"}***, "detection_identity_name": "PsExec", "threat_cleanable": false, "id": "f1562f29-6f0a-4588-af4d-7ea5cb473262", "dhost": "Lightning-lauat321ys", "threat": "PsExec", "suser": "Domain\\Lightning-zdko5xt0fh", ***"customer_id": "b87754e4-8a8b-4d12-8129-90f93529d81d"***, "type": "Event::Endpoint::Threat::PuaCleanupFailed", ***"event_service_event_id": "f1562f29-6f0a-4588-af4d-7ea5cb473262"***, "description": "Manual PUA cleanup required: 'PsExec' at 'C:\\Program Files (x86)\\Trojan Horse\\bin\\eicar.com'"}
 
