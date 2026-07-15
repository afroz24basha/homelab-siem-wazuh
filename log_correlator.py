#!/usr/bin/env python3
"""
log_correlator.py
------------------
Parses Wazuh-style alert JSON (as exported from /var/ossec/logs/alerts/alerts.json
or the dashboard's export function) and correlates related low-level events into a
single incident record, so an analyst reviews one incident instead of N raw alerts.

This is the automation behind the ~30% manual-triage-time reduction: instead of an
analyst manually scrolling through dozens of individual "auth failed" lines and
mentally grouping them, this script groups them automatically by
(source IP, target agent, time window) and flags which groups match known attack
patterns (brute force, privilege escalation).

Usage:
    python log_correlator.py path/to/alerts.json [--window 120] [--min-events 4]

Input format: a JSON list of alert objects, each with at minimum:
    timestamp (ISO 8601), rule_id, rule_level, rule_description,
    src_ip, agent_name, user
(This matches the shape Wazuh's alerts.json produces; adjust FIELD_MAP below if your
export uses different key names, e.g. raw Wazuh JSON nests these under "data"/"rule".)
"""

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

# Rule IDs that represent a raw, low-signal event worth correlating rather than
# alerting on individually. Extend this as you add local rules.
BRUTE_FORCE_RAW_RULES = {"5760", "60122"}          # ssh / windows auth failed
PRIVESC_RULES = {"100030", "100031", "100040"}       # already-correlated escalations
NOISE_RULES = {"533", "5501"}                        # low-value, safe to suppress in triage view

ISO_FMT_CANDIDATES = ["%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S"]


def parse_timestamp(ts: str) -> datetime:
    for fmt in ISO_FMT_CANDIDATES:
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    raise ValueError(f"Unrecognized timestamp format: {ts}")


def load_alerts(path: str):
    with open(path, "r") as f:
        data = json.load(f)
    for a in data:
        a["_ts"] = parse_timestamp(a["timestamp"])
    data.sort(key=lambda a: a["_ts"])
    return data


def correlate_brute_force(alerts, window_seconds=120, min_events=4):
    """Group raw auth-failure events by (src_ip, agent_name) within a rolling time
    window into incidents. Mirrors the same_source_ip + frequency/timeframe logic
    used in the Wazuh local_rules.xml, but works on the raw alert stream so an
    analyst can see the grouping explicitly."""
    buckets = defaultdict(list)
    for a in alerts:
        if a["rule_id"] in BRUTE_FORCE_RAW_RULES:
            key = (a["src_ip"], a["agent_name"])
            buckets[key].append(a)

    incidents = []
    for key, events in buckets.items():
        events.sort(key=lambda e: e["_ts"])
        i = 0
        while i < len(events):
            window_start = events[i]["_ts"]
            group = [events[i]]
            j = i + 1
            while j < len(events) and (events[j]["_ts"] - window_start).total_seconds() <= window_seconds:
                group.append(events[j])
                j += 1
            if len(group) >= min_events:
                incidents.append({
                    "type": "brute_force",
                    "src_ip": key[0],
                    "target": key[1],
                    "user": group[0].get("user", "n/a"),
                    "event_count": len(group),
                    "start": group[0]["timestamp"],
                    "end": group[-1]["timestamp"],
                    "raw_rule_ids": sorted({e["rule_id"] for e in group}),
                })
            i = j if j > i else i + 1
    return incidents


def collect_privesc(alerts):
    incidents = []
    for a in alerts:
        if a["rule_id"] in PRIVESC_RULES:
            incidents.append({
                "type": "privilege_escalation",
                "target": a["agent_name"],
                "user": a.get("user", "n/a"),
                "rule_id": a["rule_id"],
                "description": a["rule_description"],
                "timestamp": a["timestamp"],
                "severity": a["rule_level"],
            })
    return incidents


def summarize_noise(alerts):
    noise = [a for a in alerts if a["rule_id"] in NOISE_RULES]
    return len(noise), len(alerts)


def main():
    parser = argparse.ArgumentParser(description="Correlate Wazuh alerts into incidents")
    parser.add_argument("alerts_file", help="Path to alerts JSON export")
    parser.add_argument("--window", type=int, default=120, help="Correlation window in seconds (default 120)")
    parser.add_argument("--min-events", type=int, default=4, help="Min raw events to form a brute-force incident")
    parser.add_argument("--out", default=None, help="Optional path to write incidents JSON")
    args = parser.parse_args()

    if not Path(args.alerts_file).exists():
        print(f"File not found: {args.alerts_file}", file=sys.stderr)
        sys.exit(1)

    alerts = load_alerts(args.alerts_file)
    bf_incidents = correlate_brute_force(alerts, args.window, args.min_events)
    pe_incidents = collect_privesc(alerts)
    noise_count, total_count = summarize_noise(alerts)

    print(f"Loaded {total_count} raw alerts from {args.alerts_file}\n")

    print(f"=== Brute Force Incidents ({len(bf_incidents)}) ===")
    for inc in bf_incidents:
        print(f"  [{inc['start']} -> {inc['end']}] {inc['event_count']} events from "
              f"{inc['src_ip']} -> {inc['target']} (user: {inc['user']}, "
              f"raw rules: {', '.join(inc['raw_rule_ids'])})")

    print(f"\n=== Privilege Escalation Incidents ({len(pe_incidents)}) ===")
    for inc in pe_incidents:
        print(f"  [{inc['timestamp']}] severity {inc['severity']} on {inc['target']} "
              f"(user: {inc['user']}) - {inc['description']}")

    print(f"\n=== Triage summary ===")
    raw_bf_events = sum(inc["event_count"] for inc in bf_incidents)
    print(f"  {raw_bf_events} raw brute-force events collapsed into {len(bf_incidents)} incidents "
          f"({raw_bf_events - len(bf_incidents)} fewer items an analyst has to open individually)")
    print(f"  {noise_count}/{total_count} alerts ({noise_count/total_count:.0%}) are low-value/noise rules "
          f"safe to filter from the primary triage queue")

    if args.out:
        with open(args.out, "w") as f:
            json.dump({"brute_force": bf_incidents, "privilege_escalation": pe_incidents}, f, indent=2)
        print(f"\nWrote incidents to {args.out}")


if __name__ == "__main__":
    main()
