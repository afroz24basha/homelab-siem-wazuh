# Detection Rules — Brute Force & Privilege Escalation

Custom rules live in `/var/ossec/etc/rules/local_rules.xml` on the manager. Wazuh's default ruleset already flags raw auth failures; these local rules add **correlation** (multiple failures → single high-severity alert) which is what actually makes an analyst's queue usable.

## 1. SSH brute force (Linux target)

```xml
<group name="local,syslog,sshd,">
  <rule id="100010" level="10" frequency="6" timeframe="120">
    <if_matched_sid>5760</if_matched_sid>
    <same_source_ip />
    <description>SSH brute force attempt: 6+ failed logins from same source in 2 minutes</description>
    <mitre>
      <id>T1110.001</id>
    </mitre>
    <group>authentication_failures,pci_dss_10.2.4,pci_dss_10.2.5,</group>
  </rule>

  <rule id="100011" level="12" frequency="3" timeframe="60">
    <if_matched_sid>100010</if_matched_sid>
    <same_source_ip />
    <description>Repeated SSH brute force bursts from same source — likely automated attack tool</description>
    <mitre>
      <id>T1110.001</id>
    </mitre>
  </rule>
</group>
```
Rule 5760 is Wazuh's built-in "sshd authentication failed." 100010 escalates severity when the same source IP fails 6+ times in 2 minutes; 100011 catches an attacker who paces attempts to dodge the first threshold.

## 2. RDP / Windows logon brute force

```xml
<group name="local,windows,authentication_failed,">
  <rule id="100020" level="10" frequency="8" timeframe="180">
    <if_matched_sid>60122</if_matched_sid>
    <same_source_ip />
    <description>Windows brute force: 8+ failed logons (Event 4625) from same source in 3 minutes</description>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>
</group>
```

## 3. Linux privilege escalation (sudo abuse / SUID)

```xml
<group name="local,privilege_escalation,">
  <rule id="100030" level="12">
    <if_sid>530</if_sid>
    <match>COMMAND=/usr/bin/passwd</match>
    <user>root</user>
    <description>Suspicious root password change via sudo</description>
    <mitre>
      <id>T1548.003</id>
    </mitre>
  </rule>

  <rule id="100031" level="12">
    <if_sid>594</if_sid>
    <field name="audit.key">privesc_watch</field>
    <field name="audit.success">yes</field>
    <description>New SUID/EUID=0 execve detected via auditd watch (possible privilege escalation)</description>
    <mitre>
      <id>T1548.001</id>
    </mitre>
  </rule>
</group>
```

## 4. Windows privilege escalation (new admin group member)

```xml
<group name="local,windows,privilege_escalation,">
  <rule id="100040" level="12">
    <if_sid>60106</if_sid>
    <match>Administrators</match>
    <description>Account added to local Administrators group — possible privilege escalation</description>
    <mitre>
      <id>T1098</id>
    </mitre>
  </rule>
</group>
```

## Tuning process (how the ~20% false-positive reduction was achieved)

1. **Baseline measurement.** Ran the lab for 5 days under normal (non-attack) load and logged total alert volume by rule ID using `scripts/trend_report.py`.
2. **Identified noisy rules.** Default rules like generic "first time this IP has connected" and repeated Windows Defender scan-completion events accounted for a disproportionate share of low-value alerts.
3. **Applied fixes, one variable at a time, documenting each in `CHANGELOG.md`:**
   - Added `<same_source_ip/>` and frequency/timeframe thresholds to auth-failure rules instead of alerting on every single failure (biggest single reduction).
   - Whitelisted known-good admin source IPs for legitimate remote access using `<srcip negate="yes">`.
   - Raised the level of low-signal default rules from 7 → 3 so they log but don't page/alert.
   - Suppressed duplicate Windows Defender "no threats found" events via `<options>no_full_log</options>` + a low-level override.
4. **Re-measured** over another 5-day window with identical traffic patterns; compared alert-to-true-positive ratio before/after.
5. **Result:** total alert volume down ~20% with no reduction in true-positive detections during the same simulated attack runs (see `docs/03_threat_simulation_playbook.md` for the attacks used to validate this).

## Validating a rule after editing

```bash
sudo /var/ossec/bin/wazuh-logtest        # interactively test a raw log line against the ruleset
sudo /var/ossec/bin/wazuh-control restart
```
