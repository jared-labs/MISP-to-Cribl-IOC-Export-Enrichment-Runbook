# MISP → Cribl IOC Export & Enrichment — Omada SDN Log Enrichment via MISP Lookups

> Export IOCs (IPs + domains) from MISP on VMCTI01 into Cribl Stream lookup tables on VMCRIB01, enrich Omada SDN logs in-flight, and forward enriched events to Graylog on VMGRAY01.

---

## At a Glance

| Field | Value |
|-------|-------|
| **VMCTI01 — MISP** | |
| VM/CT Name | `VMCTI01` |
| Hostname / FQDN | `vmcti01` / `misp.vmcti01.lan` |
| OS | Ubuntu Server 24.04 |
| Service | MISP (HTTPS, REST API enabled) |
| **VMCRIB01 — Cribl Stream** | |
| VM/CT Name | `VMCRIB01` |
| Hostname | `vmcrib01` |
| OS | Ubuntu Server 24.04 |
| Cribl Install Root | `/opt/cribl` |
| Cribl Data Dir | `/opt/cribl/data` |
| Lookup Directory | `/opt/cribl/data/lookups/` |
| **VMGRAY01 — Graylog** | |
| VM/CT Name | `VMGRAY01` |
| Hostname | `vmgray01` |
| OS | Ubuntu Server 24.04 |
| Role | Receives enriched logs from Cribl; streams `misp_hit:true` events |
| **Omada SDN Logs** | |
| Pipeline | `omada-sdn` (in Cribl) |
| Parsed Fields | `src_ip`, `dst_ip` (minimum) |
| Depends On | MISP (IOC source), Cribl (enrichment engine), Graylog (destination) |

---

## Prerequisites

- [ ] MISP running on VMCTI01 with REST API enabled
- [ ] Cribl Stream running on VMCRIB01
- [ ] Graylog running on VMGRAY01 and receiving logs from Cribl
- [ ] Omada SDN logs already flowing into Cribl (`omada-sdn` pipeline) with `src_ip` and `dst_ip` parsed
- [ ] Network connectivity: VMCRIB01 can reach MISP on HTTPS
- [ ] `curl` installed on VMCRIB01

---

## 1 — MISP API User for Cribl

### 1.1 Create a Dedicated Automation User

In the MISP web UI (`https://misp.vmcti01.lan`):

1. Login as a MISP administrator.
2. Go to `Administration → List Users` (or `Administration → Add User`).
3. Create a new user:
   - Email: `cti_api@homelab.lan`
   - Organisation: Your primary homelab org (e.g. `Homelab`).
   - Authkey: leave blank (MISP will generate one).
   - Set a strong password (even if you only use the API key).

### 1.2 Assign Role / Permissions

The user needs to read attributes/events (including feeds and warninglist-governed objects).

Typical working choices:

- Role: `Org Admin`, `Sync user`, or another role that:
  - Can access events and attributes in your main org.
  - Can see feed data and warninglist-filtered attributes.

> **Quirk – feeds/warninglists visibility:** When we tried a more limited role (e.g. read-only or a custom restricted role), REST search came back empty or only saw a subset of attributes. Promoting the user to a role with feed and warninglist visibility (e.g. `Org admin` or `Sync user`) resolved it. If your CSVs are empty even though MISP has data, **check the role**.

### 1.3 Generate & Capture API Key (Authkey)

1. Open the user: `Administration → List Users → cti_api@homelab.lan`
2. Click "Edit" or "View" and locate the **Authkey** section.
3. Click "GenerateAuthkey" if needed.
4. Copy the Authkey — this is the `API_KEY` used on VMCRIB01.

> **Storage recommendation:** Store it in a password manager (Vaultwarden on VMVLT01) and paste into the script as a placeholder. Do **not** commit the real key to GitHub; use a placeholder like `CHANGEME_MISP_API_KEY` in your repo.

---

## 2 — Export Script on VMCRIB01

### 2.1 Create Directories

```bash
sudo mkdir -p /opt/cribl/bin
sudo mkdir -p /opt/cribl/data/lookups
```

> **Quirk – path confusion:** Cribl UI expects lookups under `/opt/cribl/data/lookups/`. We originally wrote to `/opt/cribl/lookups/`, saw duplicate files, and wondered why the UI didn't update. Standardize on `/opt/cribl/data/lookups/` for IOC exports.

### 2.2 Create `/opt/cribl/bin/misp_export_iocs.sh`

```bash
sudo nano /opt/cribl/bin/misp_export_iocs.sh
```

Paste:

```bash
#!/usr/bin/env bash
set -euo pipefail

#
# MISP → CSV export for Cribl lookups
#
# - Exports IP IOCs and domain/hostname IOCs as CSV
# - Applies MISP warninglists
# - Only includes attributes with to_ids=true and published=true
#

# Base MISP URL (HTTPS)
MISP_URL="${MISP_URL:-https://misp.vmcti01.lan}"

# API key (Authkey) for cti_api@homelab.lan
# Override at runtime with MISP_API_KEY env var if desired
API_KEY="${MISP_API_KEY:-CHANGEME_MISP_API_KEY}"

# Lookup directory used by Cribl UI
LOOKUP_DIR="/opt/cribl/data/lookups"

# Output CSV paths
IPS_FILE="${LOOKUP_DIR}/misp_ips.csv"
DOMAINS_FILE="${LOOKUP_DIR}/misp_domains.csv"

# Use -k if you have a self-signed MISP certificate.
# Remove -k once MISP has a trusted certificate.
CURL_OPTS=( -sS -k -X POST
  -H "Authorization: ${API_KEY}"
  -H "Accept: text/csv"
  -H "Content-Type: application/json"
)

mkdir -p "${LOOKUP_DIR}"

# Build JSON bodies for the two searches
IP_QUERY="$(cat << 'EOF'
{
  "returnFormat": "csv",
  "type": ["ip-src", "ip-dst"],
  "to_ids": true,
  "published": true,
  "enforceWarninglist": 1
}
EOF
)"

DOMAIN_QUERY="$(cat << 'EOF'
{
  "returnFormat": "csv",
  "type": ["domain", "hostname"],
  "to_ids": true,
  "published": true,
  "enforceWarninglist": 1
}
EOF
)"

timestamp() {
  date -Iseconds
}

echo "$(timestamp) [INFO] Starting MISP IOC export..."

# Export IPs
echo "$(timestamp) [INFO] Fetching IP attributes from MISP..."
TMP_IPS="${IPS_FILE}.tmp"
/usr/bin/curl "${CURL_OPTS[@]}" \
  "${MISP_URL}/attributes/restSearch" \
  -d "${IP_QUERY}" \
  > "${TMP_IPS}"

# Export domains/hostnames
echo "$(timestamp) [INFO] Fetching domain/hostname attributes from MISP..."
TMP_DOMAINS="${DOMAINS_FILE}.tmp"
/usr/bin/curl "${CURL_OPTS[@]}" \
  "${MISP_URL}/attributes/restSearch" \
  -d "${DOMAIN_QUERY}" \
  > "${TMP_DOMAINS}"

# Basic sanity check: files exist and are non-empty (they may still have only headers)
if [ ! -s "${TMP_IPS}" ]; then
  echo "$(timestamp) [WARN] IP CSV appears empty (no rows)."
fi

if [ ! -s "${TMP_DOMAINS}" ]; then
  echo "$(timestamp) [WARN] Domain CSV appears empty (no rows)."
fi

# Atomic move into place so Cribl never sees partial files
mv "${TMP_IPS}" "${IPS_FILE}"
mv "${TMP_DOMAINS}" "${DOMAINS_FILE}"

# Ensure Cribl (running as non-root) can read the files
chmod 0644 "${IPS_FILE}" "${DOMAINS_FILE}"

# Log row counts (including header row)
IP_LINES=$(wc -l < "${IPS_FILE}" || echo 0)
DOMAIN_LINES=$(wc -l < "${DOMAINS_FILE}" || echo 0)

echo "$(timestamp) [INFO] Wrote ${IPS_FILE} (${IP_LINES} lines)"
echo "$(timestamp) [INFO] Wrote ${DOMAINS_FILE} (${DOMAIN_LINES} lines)"
echo "$(timestamp) [INFO] MISP IOC export complete."
```

Make it executable:

```bash
sudo chmod +x /opt/cribl/bin/misp_export_iocs.sh
```

### 2.3 Manual Test (as root)

```bash
sudo /opt/cribl/bin/misp_export_iocs.sh
```

Check output:

```bash
sudo ls -l /opt/cribl/data/lookups/misp_*.csv
sudo wc -l /opt/cribl/data/lookups/misp_ips.csv
sudo wc -l /opt/cribl/data/lookups/misp_domains.csv
```

Example output (will vary by environment):

```
-rw-r--r-- 1 root root  8123 Nov 23 21:10 /opt/cribl/data/lookups/misp_ips.csv
-rw-r--r-- 1 root root 10456 Nov 23 21:10 /opt/cribl/data/lookups/misp_domains.csv

125 /opt/cribl/data/lookups/misp_ips.csv
153 /opt/cribl/data/lookups/misp_domains.csv
```

### 2.4 Permissions Quirk

- Running the script as non-root `cribl_admin` failed to write `*.tmp` into `/opt/cribl/data/lookups` due to ownership/permissions.
- Mixing root-owned and non-root-owned files in the lookup directory made debugging harder.
- **Final decision:** Run the script as **root** via root's crontab. Keep files mode `0644` so the Cribl service user can read them.

Testing the script without `sudo` will produce permission errors if your current user doesn't own `/opt/cribl/data/lookups`. This is normal once cron runs it as root.

---

## 3 — Cron Job on VMCRIB01

### 3.1 Install and Enable Cron

```bash
sudo apt update
sudo apt install -y cron
sudo systemctl enable --now cron
sudo systemctl status cron
```

Confirm it's `active (running)`.

### 3.2 Root Crontab Entry

```bash
sudo crontab -e
```

Add (every 4 hours):

```bash
0 */4 * * * /opt/cribl/bin/misp_export_iocs.sh >/var/log/misp_export_iocs.log 2>&1
```

Confirm:

```bash
sudo crontab -l
```

### 3.3 Validate Scheduled Execution

After at least one cron run:

```bash
sudo tail -n 50 /var/log/misp_export_iocs.log
sudo ls -l /opt/cribl/data/lookups/misp_*.csv
sudo wc -l /opt/cribl/data/lookups/misp_ips.csv
sudo wc -l /opt/cribl/data/lookups/misp_domains.csv
```

If `wc -l` reports `0` or `1` for an unexpectedly empty lookup, double-check:

- MISP has matching attributes (`ip-src`/`ip-dst`/`domain`/`hostname`).
- `to_ids` is set for those attributes.
- They are part of published events.
- The `cti_api` role can see those attributes.

---

## 4 — Registering Lookup Files in Cribl

All steps in this section are done in the **Cribl Stream UI** on VMCRIB01.

### 4.1 Verify Cribl Sees the Lookup Files

In the Cribl UI go to `Knowledge → Lookups` and click **Add Lookup** (or edit existing).

For **misp_ips.csv**:

- Name: `misp_ips`
- Type: CSV
- Path: `/opt/cribl/data/lookups/misp_ips.csv`
- Key column from CSV: `value` (the IOC value column from MISP)
- Reload period (sec): see below

For **misp_domains.csv**:

- Name: `misp_domains`
- Type: CSV
- Path: `/opt/cribl/data/lookups/misp_domains.csv`
- Key column: `value`
- Reload period (sec): same concept

### 4.2 Reload Period (sec) Quirk

- Default: `-1` — meaning "load once and never refresh".
- With cron updating the CSV every 4 hours, Cribl **won't** see new data unless you manually hit "Reload"/"Deploy" or change the reload period.
- **Fix:** Set reload period to a positive value, e.g.:
  - `3600` (reload every hour), or
  - `900` (reload every 15 minutes) during testing.
- During initial testing, temporarily set a tiny reload (e.g. `5` seconds) to confirm updates, then bump back.

> **Important:** Any change to lookup configuration requires a **Deploy** in Cribl for the change to take effect.

---

## 5 — Omada Pipeline Enrichment (IP → MISP)

Assumes an existing pipeline named `omada-sdn` with `src_ip` and `dst_ip` already parsed as strings.

### 5.1 Lookup: Destination IP (`dst_ip` → MISP IPs)

Add a **Lookup** function near the top of the pipeline (after parsing):

- Name: `lookup_misp_dst_ip`
- Condition: `has_field("dst_ip")`
- Lookup: `misp_ips`
- Lookup key (CSV column): `value`
- Event field to match: `dst_ip`
- Output mapping table (CSV → event field):
  - `value` → `misp_dst_value`
  - `event_id` → `misp_dst_event_id`
  - `comment` → `misp_dst_comment`
  - `category` → `misp_dst_category`
  - `type` → `misp_dst_type`
  - `uuid` → `misp_dst_uuid`

> **Critical mapping direction quirk:** We initially reversed the mapping (configured `lookupField: misp_dst_value` and `eventField: value`), which meant Cribl tried to match `misp_dst_value` from the event against the CSV — which never existed — so we got **no hits**. Correct is: **Event field** = `dst_ip`, **CSV key column** = `value`, Output fields go **from CSV to new event fields**.

### 5.2 Lookup: Source IP (`src_ip` → MISP IPs)

Add a second **Lookup** function:

- Name: `lookup_misp_src_ip`
- Condition: `has_field("src_ip")`
- Lookup: `misp_ips`
- Lookup key (CSV column): `value`
- Event field to match: `src_ip`
- Output mapping table:
  - `value` → `misp_src_value`
  - `event_id` → `misp_src_event_id`
  - `comment` → `misp_src_comment`
  - `category` → `misp_src_category`
  - `type` → `misp_src_type`
  - `uuid` → `misp_src_uuid`

### 5.3 Eval: Hit Flags and Side

Add an **Eval** function:

- Filter: `true`
- Evaluate Fields:
  - `misp_dst_hit` → `!!misp_dst_value`
  - `misp_src_hit` → `!!misp_src_value`
  - `misp_hit` → `misp_dst_hit || misp_src_hit`
  - `misp_indicator_side` →

```javascript
misp_dst_hit && misp_src_hit ? "both" :
misp_dst_hit ? "dst" :
misp_src_hit ? "src" :
null
```

> **Quirk – Eval filter vs Evaluate fields:** We initially pasted multi-line JS (with `const` declarations) into the **Eval Filter** field, expecting it to "just work". This caused syntax errors because the Filter is supposed to be a single boolean expression. Correct approach: set Filter to `true` and put all JS expressions into **Evaluate fields** rows.

### 5.4 Eval: Primary MISP Context + Event URL

Add another **Eval** function (or reuse the same one):

- Filter: `true`
- Evaluate fields:
  - `misp_event_id` → `misp_dst_event_id || misp_src_event_id`
  - `misp_comment` → `misp_dst_comment || misp_src_comment`
  - `misp_category` → `misp_dst_category || misp_src_category`
  - `misp_type` → `misp_dst_type || misp_src_type`
  - `misp_event_url` →

```javascript
misp_event_id ?
  "https://misp.vmcti01.lan/events/view/" + misp_event_id :
  null
```

This prefers the destination side if both sides matched (because it checks `dst` first) and gives you a single `misp_event_url` you can click in Graylog to open the event in MISP.

---

## 6 — Testing & Caching Gotchas

### 6.1 Positive Test with a Known IP

1. In MISP, create a test event:
   - Attribute: `ip-dst` or `ip-src`
   - Value: an internal lab IP (e.g. `10.0.0.1`)
   - Set `to_ids = true`
   - Publish the event

2. Wait for cron **or** run manually:

```bash
sudo /opt/cribl/bin/misp_export_iocs.sh
```

3. Confirm presence in the CSV:

```bash
grep 10.0.0.1 /opt/cribl/data/lookups/misp_ips.csv
```

4. In Cribl, ensure lookups reload:
   - Confirm `misp_ips` has a positive reload period.
   - Apply a quick Deploy if you changed anything.

5. Generate traffic from Omada that includes `10.0.0.1` as `dst_ip` or `src_ip`.

6. In Graylog, search for that Omada event and confirm:
   - `misp_hit:true`
   - `misp_event_id:<some id>`
   - `misp_event_url:https://misp.vmcti01.lan/events/view/<id>`

Example enriched log (simplified):

```json
{
  "src_ip": "192.168.10.25",
  "dst_ip": "10.0.0.1",
  "misp_dst_value": "10.0.0.1",
  "misp_dst_event_id": "123",
  "misp_dst_comment": "Test lab IOC",
  "misp_dst_category": "Network activity",
  "misp_dst_type": "ip-dst",
  "misp_dst_uuid": "abc123-...",
  "misp_src_value": null,
  "misp_hit": true,
  "misp_indicator_side": "dst",
  "misp_event_id": "123",
  "misp_comment": "Test lab IOC",
  "misp_category": "Network activity",
  "misp_type": "ip-dst",
  "misp_event_url": "https://misp.vmcti01.lan/events/view/123"
}
```

### 6.2 Removing the Test IP and Stale Hits

1. In MISP: remove or disable the test attribute/event, or unset `to_ids`. Ensure the event is re-published if necessary.

2. Re-run the export:

```bash
sudo /opt/cribl/bin/misp_export_iocs.sh
grep 10.0.0.1 /opt/cribl/data/lookups/misp_ips.csv || echo "Not found"
```

3. Confirm the IP is **not** present in the CSV anymore.

4. Wait for `misp_ips` lookup to reload (based on your configured reload period). Optionally, temporarily set a small reload (e.g. `5` seconds) and Deploy to force a quick refresh.

5. Generate new Omada traffic with `dst_ip=10.0.0.1` and confirm:
   - New events show `misp_hit:false` (or no `misp_*` fields).
   - Older events in Graylog will **still** show `misp_hit:true` because enrichment is done at ingest time.

> **Caching gotcha:** Seeing a hit for an IOC you just removed is usually one of: old events already enriched, CSV not yet updated (cron hadn't run), or Cribl lookup not yet reloaded. Debugging order: (1) Confirm MISP no longer returns the attribute. (2) Confirm the CSV no longer contains the value. (3) Confirm Cribl lookup reloaded. (4) Confirm you're looking at **new** events in Graylog.

---

## 7 — Downstream Usage in Graylog

### 7.1 Graylog Stream for IOC-Enriched Events

1. Create a new stream, e.g. `MISP Enriched Omada Events`.
2. Add a rule:
   - Field: `misp_hit`
   - Condition: `must be exactly`
   - Value: `true`
3. Ensure Omada messages from Cribl are routed into this stream.

### 7.2 Optional Graylog Pipeline Cleanup

If Omada logs are noisy or JSON-in-JSON heavy:

1. Create a Graylog pipeline connected to the Omada stream.
2. Add a rule that copies full original payload into `raw_event` and leaves a summarized `message`.

Example Graylog pipeline rule (conceptual):

```
rule "copy raw payload"
when
  has_field("message")
then
  set_field("raw_event", to_string($message.message));
  // Optionally:
  // set_field("message", "Omada log enriched with MISP IOC(s)");
end
```

---

## 8 — Validation

### 8.1 MISP Side

- [ ] `cti_api@homelab.lan` exists and has an Authkey
- [ ] Role permits reading events/attributes and feeds
- [ ] Attributes have `to_ids=true` and are in published events
- [ ] Hitting `/attributes/restSearch` via curl returns CSV rows when run manually

### 8.2 VMCRIB01 Script & Cron

- [ ] `/opt/cribl/bin/misp_export_iocs.sh` is executable
- [ ] Script runs cleanly as root: `sudo /opt/cribl/bin/misp_export_iocs.sh`
- [ ] Cron is enabled and running
- [ ] Root crontab includes the job line
- [ ] `/var/log/misp_export_iocs.log` shows successful runs
- [ ] `/opt/cribl/data/lookups/misp_ips.csv` and `misp_domains.csv` exist and have >1 line

### 8.3 Cribl

- [ ] `misp_ips` and `misp_domains` lookups registered with correct paths
- [ ] Lookup key column is `value`
- [ ] Reload period is a positive integer
- [ ] `omada-sdn` pipeline has `lookup_misp_dst_ip` with correct mapping (`dst_ip` → `value`)
- [ ] `omada-sdn` pipeline has `lookup_misp_src_ip` with correct mapping (`src_ip` → `value`)
- [ ] Eval function(s) compute `misp_hit` and `misp_event_url`
- [ ] Recent events with known IOCs show `misp_hit:true`

### 8.4 Graylog

- [ ] Stream for `misp_hit:true` exists and is active
- [ ] Enriched Omada messages show `misp_*` fields as expected
- [ ] You distinguish between old enriched events and new ones after changes

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| CSVs are empty despite MISP having data | `cti_api` role too restrictive | Promote to `Org admin` or `Sync user` with feed/warninglist visibility |
| Script fails with `Permission denied` on `*.tmp` | Running as non-root user | Run as root via root's crontab; keep files `0644` |
| Cribl lookups never refresh | Reload period set to `-1` (default) | Set a positive reload period (e.g. `3600`) and Deploy |
| No lookup matches for known IOCs | Mapping direction reversed in Cribl | Ensure Event field = `dst_ip`/`src_ip`, CSV key column = `value` |
| Eval syntax errors in Cribl | Multi-line JS pasted into Filter field | Set Filter to `true`; put expressions in Evaluate Fields rows |
| IOC still showing after removal from MISP | Stale cached data at one or more layers | Check: MISP → CSV → Cribl reload → new events in Graylog (in that order) |
| CSV written but Cribl UI shows old data | Files written to `/opt/cribl/lookups/` (wrong path) | Use `/opt/cribl/data/lookups/` |
| `wc -l` shows 0 or 1 lines | Attributes missing `to_ids=true` or event unpublished | Verify attributes and publish events in MISP |

---

## Quick Reference

```bash
# Run IOC export manually
sudo /opt/cribl/bin/misp_export_iocs.sh

# Check export log
sudo tail -n 50 /var/log/misp_export_iocs.log

# Verify CSV contents
sudo wc -l /opt/cribl/data/lookups/misp_ips.csv
sudo wc -l /opt/cribl/data/lookups/misp_domains.csv
grep <IOC_VALUE> /opt/cribl/data/lookups/misp_ips.csv

# View root crontab
sudo crontab -l

# Cron schedule (every 4 hours)
0 */4 * * * /opt/cribl/bin/misp_export_iocs.sh >/var/log/misp_export_iocs.log 2>&1
```

---

## Quirks & Gotchas

- **Lookup path:** Cribl expects `/opt/cribl/data/lookups/` — NOT `/opt/cribl/lookups/`. Using the wrong path causes mismatch between filesystem and the Cribl Knowledge UI.
- **Permissions:** Running the export as `cribl_admin` hits `Permission denied`. Run as root via cron; files at `0644` let Cribl read them.
- **Mapping direction:** CSV key column = `value`, Event field = `dst_ip`/`src_ip`. Reversing this yields zero matches even for known IOCs.
- **Reload interval:** Default `-1` means load-once-never-refresh. Set a positive value or Cribl will never see updated CSVs.
- **Eval filter misuse:** The Eval Filter field expects a single boolean expression. Put multi-line JS logic in "Evaluate fields" rows instead, with Filter set to `true`.
- **MISP role visibility:** A restrictive role for `cti_api@homelab.lan` can result in empty REST search results. Use `Org admin` or `Sync user` to ensure attribute/feed visibility.

---

*Last updated: 2025-XX-XX*
