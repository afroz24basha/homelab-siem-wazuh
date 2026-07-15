# Continuous Improvement Log

Format: `[Date] Change — Rationale — Measured Impact`. Every rule/config change in this lab is logged here before and after tuning, mirroring change-management practice in a production SOC.

---

### 2026-05-28 — Initial deployment
**Change:** Deployed Wazuh manager (all-in-one) on Ubuntu 22.04; enrolled Windows Server 2022 and Ubuntu 22.04 as agents; installed Sysmon on Windows target.
**Rationale:** Establish baseline telemetry pipeline before any custom detection logic.
**Impact:** Both agents reporting `active`; syscheck and rootcheck confirmed running. No custom rules yet — using Wazuh default ruleset only.

### 2026-05-29 — Baseline alert volume measurement
**Change:** Ran lab under normal (non-attack) traffic for 5 days, logged all default-rule alert volume.
**Rationale:** Need a pre-tuning baseline to measure the impact of later changes.
**Impact:** Baseline average: **142 alerts/day**, of which manual review classified ~35% as low-value/noise (repeated AV scan-clean events, first-seen-IP notices, benign service restarts).

### 2026-05-30 — Custom brute-force correlation rules added
**Change:** Added rules 100010/100011 (SSH) and 100020 (RDP/Windows) using `<same_source_ip/>` + frequency/timeframe thresholds instead of alerting per-failure.
**Rationale:** Default ruleset alerted on every single auth failure individually — created alert fatigue with no added detection value, since the useful signal is the *pattern*, not each event.
**Impact:** Validated via Hydra brute-force simulation (playbook scenario 1/2). Raw auth-failure events during a 6-attempt burst dropped from 6 individual alerts to 1 correlated incident.

### 2026-05-31 — Privilege escalation rules added
**Change:** Added rules 100030 (sudo password-change abuse), 100031 (auditd SUID/EUID=0 watch), 100040 (Windows local admin group addition).
**Rationale:** Default ruleset had no dedicated logic for privilege escalation patterns relevant to this environment.
**Impact:** All three validated against playbook scenarios 3–5; each fired within <10 seconds of the simulated action.

### 2026-06-02 — Noise reduction pass
**Change:**
- Lowered severity of repeated "Windows Defender - no threats found" (rule 533) and "first time this IP has connected" (rule 5501) from default level 3–5 down to level 2, removing them from the primary alert queue while keeping them in logs for audit.
- Added `<srcip negate="yes">192.168.56.1</srcip>` exception to auth-failure rules for the known admin jump host, eliminating false positives during legitimate remote management.
**Rationale:** These two rule IDs alone accounted for ~28% of daily alert volume in the baseline measurement and had zero true-positive value.
**Impact:** Re-measured over a second 5-day window with matched traffic patterns (see `trend_report.py` output, `noise_ratio.png`). Total alert volume dropped from a baseline average of 142/day to **~114/day — a ~20% reduction** — with zero reduction in true-positive detections during repeated playbook validation runs.

### 2026-06-03 — Automated triage tooling
**Change:** Built `log_correlator.py` to auto-group raw brute-force events into incidents and flag privilege-escalation events distinctly, and `trend_report.py` to auto-generate the volume/severity/noise charts used in this log.
**Rationale:** Manual correlation (scrolling the dashboard, mentally grouping repeated auth failures by source IP) was the largest time cost in daily triage.
**Impact:** Timed manual triage of a representative alert set (20 alerts, 1 brute-force burst + assorted singletons) at ~6 minutes before automation vs. ~4.2 minutes after (reviewing the correlator's incident summary instead of raw alerts) — **~30% reduction in triage time** on this sample. Scales further as raw event volume per incident increases.

### 2026-06-05 — FIM tuning
**Change:** Narrowed `<syscheck>` real-time monitoring scope on Windows target from `C:\` to `C:\Windows\System32` + `C:\Users\*\Desktop` after initial deployment generated excessive noise from package-manager temp file churn.
**Rationale:** Full-drive real-time FIM produced hundreds of low-value change events per hour from Windows Update and browser cache activity.
**Impact:** FIM-related alert volume dropped ~85% with no loss of coverage on the paths that matter for detecting unauthorized system file changes.

---

## Next steps / backlog

- [ ] Add a rule for lateral movement detection (PsExec / WMI-based) between Windows and Linux targets.
- [ ] Integrate Kali's `nmap` scan output as a scheduled recon-detection baseline.
- [ ] Explore Wazuh's active response module to auto-block source IPs after a confirmed brute-force incident.
