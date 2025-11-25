# MISP → Cribl IOC Export & Enrichment Runbook (VMCTI01 / VMCRIB01 / VMGRAY01)

## Overview

This runbook documents how MISP on **VMCTI01** exports IOCs (IPs + domains) to **VMCRIB01**, where Cribl Stream turns them into lookup tables used to enrich **Omada SDN** logs before forwarding into **Graylog** on **VMGRAY01**.

It covers:

- Creating a dedicated MISP automation user + API key for Cribl.
- Exporting IOCs from MISP via `/attributes/restSearch` into CSV files.
- Storing CSVs in `/opt/cribl/data/lookups/` on VMCRIB01 and refreshing them on a schedule.
- Registering and reloading CSV lookups in Cribl.
- Enriching Omada logs with MISP metadata in the `omada-sdn` pipeline.
- Downstream usage in Graylog (streams, optional field cleanup).
- Real-world quirks: paths, permissions, mapping direction, and lookup reload behavior.

* * *

## Environment / VM Context

### VMCTI01 – MISP

- Proxmox VM name: `VMCTI01`
- Hostname: `vmcti01`
- FQDN: `misp.vmcti01.lan`
- OS: Ubuntu Server 24.04
- Service: MISP (HTTPS, REST API enabled)

### VMCRIB01 – Cribl Stream

- Proxmox VM name: `VMCRIB01`
- Hostname: `vmcrib01`
- OS: Ubuntu Server 24.04
- Cribl install root: `/opt/cribl`
- Cribl binaries: `/opt/cribl/bin`
- Cribl data directory: `/opt/cribl/data`
- Lookup directory used by Cribl UI:
  - **Canonical**: `/opt/cribl/data/lookups/`
  - (We initially wrote to `/opt/cribl/lookups/` by mistake.)

### VMGRAY01 – Graylog

- Proxmox VM name: `VMGRAY01`
- Hostname: `vmgray01`
- OS: Ubuntu Server 24.04
- Graylog receives enriched logs from Cribl.
- Graylog stream/pipelines used to highlight `misp_hit:true` events.

### Omada SDN Logs

- Omada SDN logs already flowing into Cribl (`omada-sdn` pipeline).
- Parsed fields include (at minimum):
  - `src_ip`
  - `dst_ip`
- `omada-sdn` pipeline is where MISP enrichment happens.

* * *

## 1. MISP API User for Cribl

### 1.1 Create a Dedicated Automation User

In the MISP web UI (`https://misp.vmcti01.lan`):

1. Login as a MISP administrator.
2. Go to:

   - `Administration → List Users` (or `Administration → Add User` depending on your version).

3. Create a new user:

   - Email: `cti_api@homelab.lan`
   - Organisation: Your primary homelab org (e.g. `Homelab`).
   - Authkey: leave blank (MISP will generate one).
   - Set a strong password (even if you only use the API key).

### 1.2 Assign Role / Permissions

The user needs to:

- Read attributes/events (including feeds, if you rely on them).
- Have access to objects governed by warninglists/taxonomies.

Typical working choices:

- Role: `Org Admin`, `Sync user`, or another role that:
  - Can access events and attributes in your main org.
  - Can see feed data and warninglist-filtered attributes.

**Quirk – feeds/warninglists visibility**

- When we tried a more limited role (e.g. read-only or a custom restricted role), REST search came back empty or only saw a subset of attributes.
- Promoting the user to a role with feed and warninglist visibility (e.g. `Org admin` or `Sync user`) resolved it.
- If your CSVs are empty even though MISP has data, **check the role**.

### 1.3 Generate & Capture API Key (Authkey)

1. While logged in as an admin, open the user:

   - `Administration → List Users → cti_api@homelab.lan`

2. Click “Edit” or “View” and locate the **Authkey** section.
3. Click “GenerateAuthkey” if needed.
4. Copy the Authkey — this is the `API_KEY` used on VMCRIB01.

**Storage recommendation**

- Store it in a password manager (Vaultwarden on VMVLT01) and paste into the script as a placeholder.
- Do **not** commit the real key to GitHub; use a placeholder like `CHANGEME_MISP_API_KEY` in your repo.

* * *

## 2. Export Script on VMCRIB01

All of this happens on **VMCRIB01**.

### 2.1 Create Directories

Make sure `bin` and lookup directories exist:

    sudo mkdir -p /opt/cribl/bin
    sudo mkdir -p /opt/cribl/data/lookups

**Quirk – path confusion**

- Cribl UI expects lookups under: `/opt/cribl/data/lookups/`.
- We originally wrote to `/opt/cribl/lookups/`, saw duplicate files, and wondered why the UI didn’t update.
- Standardize on `/opt/cribl/data/lookups/` for IOC exports.

### 2.2 Create `/opt/cribl/bin/misp_export_iocs.sh`

Create the script as root:

    sudo nano /opt/cribl/bin/misp_export_iocs.sh

Paste:

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

Make it executable:

    sudo chmod +x /opt/cribl/bin/misp_export_iocs.sh

### 2.3 Manual Test (as root)

Run once manually as root:

    sudo /opt/cribl/bin/misp_export_iocs.sh

Check output:

    sudo ls -l /opt/cribl/data/lookups/misp_*.csv
    sudo wc -l /opt/cribl/data/lookups/misp_ips.csv
    sudo wc -l /opt/cribl/data/lookups/misp_domains.csv

Example output (will vary by environment):

    -rw-r--r-- 1 root root  8123 Nov 23 21:10 /opt/cribl/data/lookups/misp_ips.csv
    -rw-r--r-- 1 root root 10456 Nov 23 21:10 /opt/cribl/data/lookups/misp_domains.csv
    
    125 /opt/cribl/data/lookups/misp_ips.csv
    153 /opt/cribl/data/lookups/misp_domains.csv

### 2.4 Permissions Quirk

- When we originally ran the script as a non-root `cribl_admin` user:
  - The script failed to write `*.tmp` into `/opt/cribl/data/lookups` due to ownership/permissions.
  - Previous root-created files were owned by `root:root`, causing confusing `Permission denied` errors.
- Final decision:
  - **Run the script as root via root’s crontab**.
  - Keep files mode `0644` so the Cribl service user can read them.

Testing the script **without** `sudo`:

- Expect permission errors if your current user doesn’t own `/opt/cribl/data/lookups`.
- This is normal once you’ve decided cron will run it as root.

* * *

## 3. Cron Job on VMCRIB01

### 3.1 Install and Enable Cron

    sudo apt update
    sudo apt install -y cron
    sudo systemctl enable --now cron
    sudo systemctl status cron

Confirm it’s `active (running)`.

### 3.2 Root Crontab Entry

Edit root’s crontab:

    sudo crontab -e

Add (every 4 hours):

    0 */4 * * * /opt/cribl/bin/misp_export_iocs.sh >/var/log/misp_export_iocs.log 2>&1

Save and confirm:

    sudo crontab -l

You should see the line you just added.

### 3.3 Validate Scheduled Execution

After at least one cron run, check:

    sudo tail -n 50 /var/log/misp_export_iocs.log
    sudo ls -l /opt/cribl/data/lookups/misp_*.csv
    sudo wc -l /opt/cribl/data/lookups/misp_ips.csv
    sudo wc -l /opt/cribl/data/lookups/misp_domains.csv

If `wc -l` reports `0` or `1` for an unexpectedly empty lookup:

- Double-check:
  - MISP has matching attributes (ip-src/ip-dst/domain/hostname).
  - `to_ids` is set for those attributes.
  - They are part of published events.
  - The `cti_api` role can see those attributes.

* * *

## 4. Registering Lookup Files in Cribl

All steps in this section are done in the **Cribl Stream UI** on VMCRIB01.

### 4.1 Verify Cribl Sees the Lookup Files

In the Cribl UI:

1. Go to `Knowledge → Lookups`.
2. Click **Add Lookup** (or edit an existing one if you already created it).

For **misp_ips.csv**:

- Name: `misp_ips`
- Type: CSV
- Path: `/opt/cribl/data/lookups/misp_ips.csv`
- Key column from CSV: `value` (this is the IOC value column from MISP).
- Reload period (sec): see below.

For **misp_domains.csv**:

- Name: `misp_domains`
- Type: CSV
- Path: `/opt/cribl/data/lookups/misp_domains.csv`
- Key column: `value`
- Reload period (sec): same concept.

### 4.2 Reload Period (sec) Quirk

- Default: `-1`
  - Meaning: “load once and never refresh”.
  - With cron updating the CSV every 4 hours, Cribl **won’t** see new data unless:
    - You manually hit “Reload”/“Deploy”, or
    - You change the reload period.
- Fix:
  - Set reload period to something reasonable, e.g.:

    - `3600` (reload every hour), or
    - `900` (reload every 15 minutes) during testing.

- During initial testing, you can temporarily set a tiny reload (e.g. `5` seconds) to confirm updates, then bump it back to a saner value.

**Important:** Any change to lookup configuration requires a **Deploy** in Cribl for the change to take effect.

* * *

## 5. Omada Pipeline Enrichment (IP → MISP)

We assume:

- You have an existing pipeline named e.g. `omada-sdn`.
- `src_ip` and `dst_ip` are already parsed from the Omada logs and are strings.

The enrichment consists of:

1. Lookup `dst_ip` in `misp_ips`.
2. Lookup `src_ip` in `misp_ips`.
3. Eval step to mark hits and derive primary IOC context.
4. Eval step to build MISP event URL and other convenience fields.

### 5.1 Lookup: Destination IP (`dst_ip` → MISP IPs)

Add a **Lookup** function near the top of the pipeline (after parsing):

- Name: `lookup_misp_dst_ip`
- Condition: `has_field("dst_ip")`
- Lookup: `misp_ips`
- Lookup key (CSV column): `value`
- Event field to match: `dst_ip`
- Output mapping table (CSV → event field):

  - `value`     → `misp_dst_value`
  - `event_id`  → `misp_dst_event_id`
  - `comment`   → `misp_dst_comment`
  - `category`  → `misp_dst_category`
  - `type`      → `misp_dst_type`
  - `uuid`      → `misp_dst_uuid`

**Critical mapping direction quirk**

- We initially reversed the mapping (configured something like `lookupField: misp_dst_value` and `eventField: value`), which meant:
  - Cribl tried to match `misp_dst_value` from the event against the CSV, which never existed, so we got **no hits**.
- Correct is:
  - **Event field**: `dst_ip`
  - **CSV key column**: `value`
  - Output fields are **from CSV to new event fields** as shown above.

### 5.2 Lookup: Source IP (`src_ip` → MISP IPs)

Add a second **Lookup** function:

- Name: `lookup_misp_src_ip`
- Condition: `has_field("src_ip")`
- Lookup: `misp_ips`
- Lookup key (CSV column): `value`
- Event field to match: `src_ip`
- Output mapping table:

  - `value`     → `misp_src_value`
  - `event_id`  → `misp_src_event_id`
  - `comment`   → `misp_src_comment`
  - `category`  → `misp_src_category`
  - `type`      → `misp_src_type`
  - `uuid`      → `misp_src_uuid`

This gives you separate MISP metadata for source and destination sides.

### 5.3 Eval: Hit Flags and Side

Add an **Eval** function with:

- Filter: `true` (run on all events).
- Under **Evaluate Fields**, add:

  - Field: `misp_dst_hit`
    - Expression: `!!misp_dst_value`
  - Field: `misp_src_hit`
    - Expression: `!!misp_src_value`
  - Field: `misp_hit`
    - Expression: `misp_dst_hit || misp_src_hit`
  - Field: `misp_indicator_side`
    - Expression:

      - Example logic:

        - If both sides hit: `"both"`
        - Else if dst hit: `"dst"`
        - Else if src hit: `"src"`
        - Else: `null`

    - One way to express this in Cribl JS:

        misp_dst_hit && misp_src_hit ? "both" :
        misp_dst_hit ? "dst" :
        misp_src_hit ? "src" :
        null

**Quirk – Eval filter vs Evaluate fields**

- At first we pasted multi-line JS (with `const` declarations) into the **Eval Filter** field, expecting it to “just work”.
  - This caused syntax errors because the Filter is supposed to be a single boolean expression.
- Correct approach:
  - Set Filter: `true`.
  - Put all of your JS expressions into **Evaluate fields** rows instead.

### 5.4 Eval: Primary MISP Context + Event URL

Add another **Eval** function (or reuse the same one, separated logically):

- Filter: `true`
- Evaluate fields:

  - Field: `misp_event_id`
    - Expression: `misp_dst_event_id || misp_src_event_id`
  - Field: `misp_comment`
    - Expression: `misp_dst_comment || misp_src_comment`
  - Field: `misp_category`
    - Expression: `misp_dst_category || misp_src_category`
  - Field: `misp_type`
    - Expression: `misp_dst_type || misp_src_type`
  - Field: `misp_event_url`
    - Expression:

        misp_event_id ?
          "https://misp.vmcti01.lan/events/view/" + misp_event_id :
          null

This:

- Prefers the destination side if both sides matched (because it checks `dst` first).
- Gives you a single `misp_event_url` you can click in Graylog to open the event in MISP.

* * *

## 6. Testing & Caching Gotchas

### 6.1 Positive Test with a Known IP

1. In MISP, create a test event:

   - Attribute: `ip-dst` or `ip-src`
   - Value: an internal lab IP (e.g. `10.0.0.1`)
   - Set `to_ids = true`.
   - Publish the event.

2. Wait for the next cron run **or** manually run:

    sudo /opt/cribl/bin/misp_export_iocs.sh

3. Confirm presence in the CSV:

    grep 10.0.0.1 /opt/cribl/data/lookups/misp_ips.csv

4. In Cribl, ensure lookups reload:

   - Confirm `misp_ips` has a positive reload period.
   - Apply a quick Deploy if you changed anything.

5. Generate traffic from Omada that includes `10.0.0.1` as `dst_ip` or `src_ip`.

6. In Graylog, search for that Omada event and confirm:

   - `misp_hit:true`
   - `misp_event_id:<some id>`
   - `misp_event_url:https://misp.vmcti01.lan/events/view/<id>`

Example enriched log (simplified):

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
      "misp_event_url": "https://misp.vmcti01.lan/events/view/123",
      ...
    }

### 6.2 Removing the Test IP and Stale Hits

1. In MISP:

   - Remove or disable the test attribute/event, or unset `to_ids`.
   - Ensure the event is re-published if necessary.

2. Re-run the export:

    sudo /opt/cribl/bin/misp_export_iocs.sh
    grep 10.0.0.1 /opt/cribl/data/lookups/misp_ips.csv || echo "Not found"

3. Confirm the IP is **not** present in the CSV anymore.

4. Wait for `misp_ips` lookup to reload:

   - Based on your configured reload period (e.g. 900 or 3600 seconds).
   - Optionally, temporarily set a small reload (e.g. 5 seconds) and Deploy to force a quick refresh.

5. Generate new Omada traffic with `dst_ip=10.0.0.1` and confirm:

   - New events show `misp_hit:false` (or no `misp_*` fields).
   - Older events in Graylog will **still** show `misp_hit:true` because enrichment is done at ingest time.

**Caching gotcha**

- Seeing a hit for an IOC you just removed is usually one of:
  - Old events already enriched.
  - CSV not yet updated (cron hadn’t run).
  - Cribl lookup not yet reloaded.
- Working order for debugging:
  1. Confirm MISP no longer returns the attribute.
  2. Confirm the CSV no longer contains the value.
  3. Confirm Cribl lookup reloaded.
  4. Confirm you’re looking at **new** events in Graylog.

* * *

## 7. Downstream Usage in Graylog

### 7.1 Graylog Stream for IOC-Enriched Events

In Graylog:

1. Create a new stream, e.g. `MISP Enriched Omada Events`.
2. Add a rule:

   - Field: `misp_hit`
   - Condition: `must be exactly`
   - Value: `true`

3. Ensure Omada messages from Cribl are routed into this stream (via default index or additional pipeline rules if needed).

This gives you a focused view of Omada events that matched MISP IOCs.

### 7.2 Optional Graylog Pipeline Cleanup

If Omada logs are noisy or JSON-in-JSON heavy, you can:

1. Create a Graylog pipeline connected to the Omada stream.
2. Add a rule that:

   - Copies full original payload into `raw_event`.
   - Leaves a summarized `message` for UI readability.

Example Graylog pipeline rule (conceptual, not exact syntax):

    rule "copy raw payload"
    when
      has_field("message")
    then
      set_field("raw_event", to_string($message.message));
      // Optionally:
      // set_field("message", "Omada log enriched with MISP IOC(s)");
    end

This is optional but helps keep the search UI clean while preserving the full raw content.

* * *

## 8. Quirks & Gotchas Summary

### 8.1 Paths

- Cribl lookup directory:

  - **Correct**: `/opt/cribl/data/lookups/`
  - **Incorrect (initial attempt)**: `/opt/cribl/lookups/`

- Using the wrong path caused:
  - Confusion about where CSVs lived.
  - Mismatch between files in the filesystem and what Cribl’s Knowledge UI showed.

### 8.2 Permissions

- Running the export script as `cribl_admin` in `/opt/cribl/data/lookups` hit `Permission denied` on `*.tmp`.
- Mixing root-owned and non-root-owned files in the lookup directory made debugging harder.
- Final approach:
  - Script runs as **root** via root cron.
  - Files are `0644`, readable by Cribl.

### 8.3 Lookup Mapping Direction

- Wrong configuration (what we initially did):
  - Treated event field as the CSV output field and CSV key as the event field.
  - Result: no matches, even for known IOCs.
- Correct configuration:
  - CSV key column: `value`
  - Event field to match: `dst_ip`/`src_ip`
  - Output: `value` → `misp_dst_value` (and similar `misp_src_*` fields).

### 8.4 Reload Interval

- Default reload period of `-1`:
  - Cribl reads the CSV once at startup and never refreshes.
  - Cron can happily overwrite CSVs without Cribl ever noticing.
- Fix:
  - Set a positive reload period (e.g. `3600` seconds).
  - During testing, temporarily set a smaller value (e.g. `5` or `30` seconds) and then increase it.

### 8.5 Eval Function Usage

- Mistake:
  - Pasting multi-line JavaScript into the Eval **Filter** box.
  - Filter expects a single boolean expression, so this produced syntax errors.
- Fix:
  - Set Filter: `true`.
  - Put JS expressions into “Evaluate fields” rows.

### 8.6 MISP Role / Visibility

- A restrictive role for `cti_api@homelab.lan` meant:
  - REST search returned no rows even though data existed.
- Fix:
  - Assign a role with appropriate visibility (`Org admin`, `Sync user`, or similar).
  - Confirm the user can see the same attributes in the UI that you expect in the exports.

* * *

## 9. Quick Sanity Checklist

Use this section when something breaks.

### 9.1 MISP Side

- [ ] `cti_api@homelab.lan` exists and has an Authkey.
- [ ] Role permits reading events/attributes and feeds.
- [ ] Attributes you expect:
  - [ ] Have `to_ids=true`.
  - [ ] Are in published events.
- [ ] Hitting `/attributes/restSearch` via curl returns CSV rows when run manually.

### 9.2 VMCRIB01 Script & Cron

- [ ] `/opt/cribl/bin/misp_export_iocs.sh` is executable.
- [ ] Script runs cleanly as root:

      sudo /opt/cribl/bin/misp_export_iocs.sh

- [ ] Cron is enabled and running.
- [ ] Root crontab includes the job line.
- [ ] `/var/log/misp_export_iocs.log` shows successful runs.
- [ ] `/opt/cribl/data/lookups/misp_ips.csv` and `misp_domains.csv` exist and have >1 line.

### 9.3 Cribl

- [ ] `misp_ips` and `misp_domains` lookups registered with correct paths.
- [ ] Lookup key column is `value`.
- [ ] Reload period is a positive integer.
- [ ] `omada-sdn` pipeline has:
  - [ ] `lookup_misp_dst_ip` with correct mapping (`dst_ip` → `value`).
  - [ ] `lookup_misp_src_ip` with correct mapping (`src_ip` → `value`).
  - [ ] Eval function(s) that compute `misp_hit` and `misp_event_url`.
- [ ] Recent events with known IOCs show `misp_hit:true`.

### 9.4 Graylog

- [ ] Stream for `misp_hit:true` exists and is active.
- [ ] Enriched Omada messages show `misp_*` fields as expected.
- [ ] You distinguish between old enriched events and new ones after changes.

If all of the above are true, you should have a reliable pipeline from **MISP → Cribl lookups → Omada log enrichment → Graylog** with MISP-aware IOC context and minimal surprises.
