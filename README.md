# MISP → Cribl IOC Export & Log Enrichment

## Overview

This document summarizes the integration pipeline between MISP (threat intelligence) and Cribl Stream (log routing) that enables real-time IOC enrichment of network events. It is written for a portfolio audience, focusing on the data flow design, export automation, and the enrichment pattern.

The pipeline exports indicators of compromise (malicious IPs and domains) from MISP into Cribl Stream lookup tables. When network events pass through Cribl, they are checked against these tables and enriched with threat context before being forwarded to the SIEM.

## Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│  VMCTI01 — MISP                                              │
│                                                              │
│  OSINT Feeds → Events → restSearch API                       │
│                              │                               │
│                              │ Scheduled export (cron)        │
│                              ▼                               │
│                    CSV files: IPs, domains                    │
└──────────────────────────────┬──────────────────────────────┘
                               │ SCP / file transfer
                               ▼
┌─────────────────────────────────────────────────────────────┐
│  VMCRIB01 — Cribl Stream                                     │
│                                                              │
│  Lookup tables:                                              │
│  ├── misp_malicious_ips.csv                                  │
│  └── misp_malicious_domains.csv                              │
│                                                              │
│  Pipeline: misp_enrich                                       │
│  ├── Lookup src_ip against misp_malicious_ips                │
│  ├── Lookup domain against misp_malicious_domains            │
│  └── Add field: threat_matched=true, threat_source=MISP      │
│                                                              │
│  Enriched events → Graylog (GELF HTTP)                       │
└─────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│  VMGRAY01 — Graylog                                          │
│  Search: threat_matched:true                                 │
│  Alert: IOC hit on network traffic                           │
└─────────────────────────────────────────────────────────────┘
```

## Design Decisions

- **CSV lookup tables over API enrichment:** Cribl's lookup function is fast (in-memory hash table) and doesn't add network latency per event. API-based enrichment (calling MISP per event) would be too slow for streaming data and fragile if MISP is temporarily unavailable.
- **Scheduled export over real-time sync:** IOC lists change slowly relative to event volume. A periodic export (e.g., hourly) keeps lookup tables fresh without overcomplicating the pipeline with event-driven sync.
- **Enrichment at the routing layer, not the SIEM:** Performing lookups in Cribl means enriched fields arrive in Graylog already indexed and searchable. No Graylog pipeline rules needed for IOC correlation.
- **Separate tables for IPs and domains:** Different lookup types (IP match vs. string match) benefit from separate, focused tables rather than one large multi-type file.

## Quirks and Gotchas

- MISP's `restSearch` API returns different formats depending on parameters — CSV export requires explicit `returnFormat=csv` and careful attribute type filtering.
- Lookup tables in Cribl need a reload after file update. The pipeline should reference the table by a stable path so automated refreshes work without config changes.
- Warninglists should be applied in MISP before export to prevent known-good IPs from polluting the lookup tables.

## What This Demonstrates

This integration shows how threat intelligence data flows from collection (MISP feeds) through normalization (export/filtering) to operational use (real-time enrichment of live log streams). The pattern — TIP → export → lookup enrichment → SIEM alerting — is a standard security operations workflow implemented with open-source tooling.

---

Sanitized for public portfolio use.

For step-by-step setup procedures, see [OPERATIONS.md](./OPERATIONS.md).
