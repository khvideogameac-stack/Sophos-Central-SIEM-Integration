# Wazuh integration

Ships the Wazuh-side pieces: rules, an `ossec.conf` snippet, and sample events
for testing. The collector side is configured with `format = wazuh` in
`config.ini`.

## Why `format = wazuh` rather than `format = json`

Both produce one JSON object per line and both are read by Wazuh with
`<log_format>json</log_format>`. The difference is field placement.

Wazuh's JSON decoder turns each top-level key into a dynamic field addressable
as `data.<key>`, except for a fixed set of names it promotes into its static
fields. Promoted fields get dedicated rule options (`<srcip>`, `<user>`,
`<url>`), GeoIP enrichment on IP fields, and variable substitution in active
response. Everything else can only be matched with `<field name="...">`.

Sophos puts the two most useful values where that cannot happen:

| Sophos field     | With `format = json`   | With `format = wazuh`             |
| ---------------- | ---------------------- | --------------------------------- |
| `source_info.ip` | `data.source_info.ip`  | also copied to `srcip` — GeoIP, `<srcip>` |
| `source`         | `data.source`          | also copied to `dstuser` — `<user>` matches |

`format = wazuh` also:

- adds `integration: sophos-central`, the single condition every rule here
  chains off;
- adds `severity_num` (0/1/5/8/10) so rules and dashboards can compare ranges
  instead of matching five separate strings;
- moves aside any top-level key that would collide with a Wazuh static field
  while carrying an object or list — alert payloads can arrive with a
  top-level `data` object, which becomes `sophos_data`.

Promotion copies rather than moves, so `data.source_info.ip` still resolves.

**But note one difference that is not a copy.** `format = json` renames fields
through the CEF mapping on the way out, and `format = wazuh` does not:

| Sophos field | `format = json` | `format = wazuh` |
| --- | --- | --- |
| `location` | `dhost` | `location` |
| `source` | `suser` | `source` + `dstuser` |
| `when` | `end` | `when` |
| `created_at` | `rt` | `created_at` |

The rules here use the `format = wazuh` names, so a dashboard keyed on
`data.dhost` needs moving to `data.location` when you switch. See
[../docs/wazuh.md](../docs/wazuh.md#migrating-from-format--json).

## Install

On the host running `siem.py`:

```ini
# config.ini
format = wazuh
filename = sophos_central.json
max_log_file_size_mb = 100      # rotate, otherwise the file grows forever
log_file_backup_count = 5
```

On the Wazuh manager:

```bash
sudo cp wazuh/rules/0910-sophos_central_rules.xml /var/ossec/etc/rules/
sudo chown root:wazuh /var/ossec/etc/rules/0910-sophos_central_rules.xml
sudo chmod 660 /var/ossec/etc/rules/0910-sophos_central_rules.xml
```

Merge the `<localfile>` block from `wazuh/ossec.conf.d/sophos-localfile.xml`
into `/var/ossec/etc/ossec.conf`, correcting the path, then:

```bash
sudo systemctl restart wazuh-manager
```

If the collector runs on a *different* host from the manager, the `<localfile>`
block goes in that host's agent `ossec.conf` instead; the rules always go on
the manager.

## Verify

Check the ruleset loads before trusting it:

```bash
sudo /var/ossec/bin/wazuh-logtest -t
```

Then feed it a sample event and confirm the rule you expect fires:

```bash
head -1 wazuh/samples/sample_events.jsonl | sudo /var/ossec/bin/wazuh-logtest
```

Line 1 of the samples should match **100210** at level 12, and show `srcip`
populated. The remaining lines exercise cleanup-failure (100212), web policy
(100230), the severity fallback (100201), an alert (100240/100241) and DLP
(100220).

Two things worth confirming against your specific Wazuh version rather than
assuming:

- **The promoted-field list.** It has shifted between minor versions. If
  `srcip` is not enriching, check your version's JSON decoder before assuming
  the mapping is wrong.
- **Rule 100291**, which combines `same_field` with `different_field`. It is
  the most version-sensitive rule in the file. Confirm with `wazuh-logtest` or
  drop it.

## Rule layout

| ID range        | Purpose                                              |
| --------------- | ---------------------------------------------------- |
| 100200          | Base rule, level 0, never alerts                     |
| 100210 – 100215 | Threat detections                                    |
| 100220          | Data loss prevention                                 |
| 100230 – 100232 | Policy and hygiene                                   |
| 100240 – 100241 | Alert stream                                         |
| 100201 – 100203 | Severity fallback for anything unmatched             |
| 100290 – 100292 | Correlation: outbreak, worm spread, cleanup failures |

Two things to know before editing:

**Order matters.** Every rule is a child of 100200, and among siblings Wazuh
takes the first that matches. Specific type rules come first, the severity
fallback last. Insert new specific rules *above* 100203.

**`<field>` uses osregex, not PCRE.** `\.` means "any character" and a bare `.`
is a literal dot, which is why the wildcard is written `\.*`.

## Tuning noise

Prefer setting a rule's level to 0 over dropping events at the collector.
`siem.py --light` excludes noisy types at the API, so those events are gone
permanently and cannot be re-examined after an incident. A local override keeps
them archived and searchable:

```xml
<!-- /var/ossec/etc/rules/0911-sophos_overrides.xml -->
<group name="sophos,">
  <rule id="100230" level="0" overwrite="yes">
    <if_sid>100200</if_sid>
    <field name="type">^Event::Endpoint::WebControlViolation$|^Event::Endpoint::WebFilteringBlocked$</field>
    <description>Sophos: web policy violation (suppressed)</description>
  </rule>
</group>
```

## Monitoring the collector itself

None of these rules fire if `siem.py` stops running — no events means no
alerts, which looks identical to a quiet day. Check liveness from the state
file, which records `lastRunAt` per tenant:

```bash
python3 -c "import json,sys,time; d=json.load(open('state/siem_sophos.json')); \
  [sys.exit('STALE: %s' % t) for t,v in d.get('tenants',{}).items() \
   if time.time() - v.get('lastRunAt',0) > 1800]"
```

Exit codes from `siem.py` are also meaningful now, so a wrapper can alert on
them: `0` ok, `1` config, `2` auth, `3` transport, `4` state, `5` already
running. See `exit_codes.py`.
