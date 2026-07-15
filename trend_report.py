#!/usr/bin/env python3
"""
trend_report.py
-----------------
Generates graphical trend reports from Wazuh alert JSON exports:
  1. Alert volume over time (daily)
  2. Top triggered rules
  3. Alert severity distribution
  4. Noise vs. actionable alert ratio (used to demonstrate the false-positive
     reduction after rule tuning)

Usage:
    python trend_report.py path/to/alerts.json [--outdir ./reports]
"""

import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

NOISE_RULES = {"533", "5501"}
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
    return data


def chart_daily_volume(alerts, outdir: Path):
    by_day = Counter(a["_ts"].date() for a in alerts)
    days = sorted(by_day)
    counts = [by_day[d] for d in days]

    plt.figure(figsize=(8, 4.5))
    plt.bar([d.isoformat() for d in days], counts, color="#2563eb")
    plt.title("Alert Volume by Day")
    plt.xlabel("Date")
    plt.ylabel("Alert Count")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    out = outdir / "daily_alert_volume.png"
    plt.savefig(out, dpi=150)
    plt.close()
    return out


def chart_top_rules(alerts, outdir: Path, top_n=8):
    by_rule = Counter((a["rule_id"], a["rule_description"]) for a in alerts)
    top = by_rule.most_common(top_n)
    labels = [f"{rid}: {desc[:30]}" for (rid, desc), _ in top]
    counts = [c for _, c in top]

    plt.figure(figsize=(9, 5))
    plt.barh(labels[::-1], counts[::-1], color="#059669")
    plt.title(f"Top {top_n} Triggered Rules")
    plt.xlabel("Count")
    plt.tight_layout()
    out = outdir / "top_rules.png"
    plt.savefig(out, dpi=150)
    plt.close()
    return out


def chart_severity_distribution(alerts, outdir: Path):
    by_level = Counter(a["rule_level"] for a in alerts)
    levels = sorted(by_level)
    counts = [by_level[l] for l in levels]

    plt.figure(figsize=(7, 4.5))
    colors = ["#16a34a" if l < 7 else "#f59e0b" if l < 11 else "#dc2626" for l in levels]
    plt.bar([str(l) for l in levels], counts, color=colors)
    plt.title("Alert Severity Distribution")
    plt.xlabel("Rule Level (Wazuh severity)")
    plt.ylabel("Count")
    plt.tight_layout()
    out = outdir / "severity_distribution.png"
    plt.savefig(out, dpi=150)
    plt.close()
    return out


def chart_noise_ratio(alerts, outdir: Path):
    noise = sum(1 for a in alerts if a["rule_id"] in NOISE_RULES)
    actionable = len(alerts) - noise

    plt.figure(figsize=(5, 5))
    plt.pie([actionable, noise], labels=["Actionable", "Low-value / noise"],
            autopct="%1.0f%%", colors=["#2563eb", "#94a3b8"], startangle=90)
    plt.title("Actionable vs. Noise Alerts")
    plt.tight_layout()
    out = outdir / "noise_ratio.png"
    plt.savefig(out, dpi=150)
    plt.close()
    return out


def main():
    parser = argparse.ArgumentParser(description="Generate SIEM trend report charts")
    parser.add_argument("alerts_file")
    parser.add_argument("--outdir", default="./reports")
    args = parser.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    alerts = load_alerts(args.alerts_file)
    if not alerts:
        print("No alerts found in input file.")
        return

    paths = [
        chart_daily_volume(alerts, outdir),
        chart_top_rules(alerts, outdir),
        chart_severity_distribution(alerts, outdir),
        chart_noise_ratio(alerts, outdir),
    ]

    print(f"Processed {len(alerts)} alerts. Generated {len(paths)} charts in {outdir}/:")
    for p in paths:
        print(f"  - {p}")


if __name__ == "__main__":
    main()
