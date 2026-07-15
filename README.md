# Home Lab: Hybrid Cloud SIEM Deployment, EDR & Threat Simulation

A self-hosted security operations lab that replicates enterprise SOC workflows: SIEM ingestion, endpoint detection, threat simulation, detection tuning, and automated triage — built entirely on VirtualBox.

## Architecture

```
                        ┌─────────────────────────────┐
                        │   Wazuh Manager (Ubuntu)     │
                        │   - Indexer (OpenSearch)     │
                        │   - Wazuh Server             │
                        │   - Dashboard (Kibana-based) │
                        │   IP: 192.168.56.10          │
                        └──────────────┬───────────────┘
                                       │  agent traffic :1514/1515
                       ┌───────────────┼────────────────┐
                       │               │                │
          ┌────────────▼───────┐ ┌─────▼──────┐  ┌──────▼────────────┐
          │ Windows Server 2022 │ │ Ubuntu 22.04│  │ Kali Linux (attack │
          │ (Domain-ish target) │ │ (Linux target)│ │  / red team host)  │
          │ Wazuh Agent + Sysmon│ │ Wazuh Agent  │  │  No agent — source │
          │ IP: 192.168.56.20   │ │192.168.56.21 │  │  of simulated attks│
          └──────────────────────┘ └──────────────┘  │  192.168.56.30     │
                                                       └────────────────────┘

    All VMs on a VirtualBox Host-Only Network (192.168.56.0/24)
    NAT adapter on each VM for internet/package updates only
```

**Why this topology mimics hybrid cloud:** the Wazuh manager plays the role of a centralized cloud-hosted SOC (as it would on an EC2/Azure VM), Windows Server and Ubuntu represent on-prem/cloud workloads reporting telemetry, and Kali represents an external/adversarial actor — the same trust model as a real hybrid environment where on-prem agents ship logs to a cloud-based SIEM.

## What's in this package

| File | Purpose |
|---|---|
| `docs/01_setup_guide.md` | Full VirtualBox + Wazuh manager/agent deployment steps |
| `docs/02_detection_rules.md` | Custom Wazuh rules for brute force & privilege escalation, plus the tuning process that cut false positives ~20% |
| `docs/03_threat_simulation_playbook.md` | Kali-based attack scenarios used to generate real detections (Hydra brute force, sudo/SUID privesc, etc.) |
| `scripts/log_correlator.py` | Parses Wazuh alert JSON, correlates related events into incidents, cuts manual triage time |
| `scripts/trend_report.py` | Generates graphical trend reports (alerts over time, top rules, false-positive rate) |
| `docs/CHANGELOG.md` | Continuous improvement log — every rule/config change with rationale and measured impact |
| `samples/sample_alerts.json` | Realistic sample Wazuh alert data so the scripts run out of the box |

## Quick start

```bash
cd scripts
pip install -r requirements.txt
python log_correlator.py ../samples/sample_alerts.json
python trend_report.py ../samples/sample_alerts.json
```

## Resume-ready summary (for reference)

- Deployed Wazuh SIEM across a VirtualBox multi-OS environment (Windows Server, Ubuntu, Kali Linux), ingesting endpoint/network telemetry and detecting brute-force and privilege-escalation activity; iteratively tuned detection rules to cut false positives ~20%.
- Built Python-based log parsing and alert correlation tooling that reduced manual triage time ~30%, with automated trend reporting and a continuous improvement log documenting every configuration change.
