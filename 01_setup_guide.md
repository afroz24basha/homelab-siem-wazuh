# Setup Guide — VirtualBox Multi-OS SIEM Lab

## 1. Host requirements

- 16 GB+ RAM on the host (4 VMs running concurrently: 4GB Wazuh manager, 4GB Windows Server, 2GB Ubuntu, 4GB Kali)
- 100+ GB free disk
- VirtualBox 7.x + Extension Pack
- ISOs: Ubuntu Server 22.04 LTS, Windows Server 2022 Evaluation, Kali Linux (VirtualBox pre-built image is fine)

## 2. Network setup

1. **File → Host Network Manager** → create a Host-Only network `vboxnet0`, subnet `192.168.56.0/24`, DHCP disabled (assign static IPs manually).
2. Each VM gets **two adapters**:
   - Adapter 1: NAT (internet access for updates/packages)
   - Adapter 2: Host-Only `vboxnet0` (lab traffic — this is the network Wazuh actually monitors)

| VM | Role | Host-Only IP |
|---|---|---|
| wazuh-manager | Ubuntu 22.04, SIEM core | 192.168.56.10 |
| win-target | Windows Server 2022 | 192.168.56.20 |
| ubuntu-target | Ubuntu 22.04 | 192.168.56.21 |
| kali-attacker | Kali Linux | 192.168.56.30 |

## 3. Deploy the Wazuh manager (Ubuntu VM)

```bash
# On wazuh-manager
sudo apt update && sudo apt upgrade -y
curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh
sudo bash wazuh-install.sh -a          # installs indexer + server + dashboard (all-in-one)
```

- Note the auto-generated `admin` password printed at the end of install — store it in a password manager.
- Dashboard: `https://192.168.56.10` (self-signed cert — expected in a lab).
- Confirm services:
```bash
sudo systemctl status wazuh-manager wazuh-indexer wazuh-dashboard
```

## 4. Enroll the Ubuntu target as an agent

```bash
# On ubuntu-target
curl -so wazuh-agent.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.9.0-1_amd64.deb
sudo WAZUH_MANAGER='192.168.56.10' dpkg -i ./wazuh-agent.deb
sudo systemctl enable --now wazuh-agent
```

Enable auditd for privilege-escalation visibility:
```bash
sudo apt install auditd -y
sudo auditctl -a always,exit -F arch=b64 -S execve -F euid=0 -k privesc_watch
```

## 5. Enroll the Windows Server target

1. Download the Wazuh agent MSI from the manager dashboard (**Agents → Deploy new agent → Windows**), which auto-fills the manager IP.
2. Install with the manager IP `192.168.56.10` and a unique agent name (`win-target`).
3. Install **Sysmon** (SwiftOnSecurity config recommended) for rich process/network telemetry — Wazuh's Windows Event Log module alone misses a lot of what Sysmon captures:
```powershell
sysmon64.exe -accepteula -i sysmonconfig-export.xml
```
4. Confirm the agent registers: on the manager, `sudo /var/ossec/bin/agent_control -l`.

## 6. Kali attacker VM

No agent installed here on purpose — Kali is the simulated adversary, not a monitored host. Just needs Host-Only network connectivity to reach 192.168.56.20/21. Install `hydra`, `nmap`, `metasploit-framework` (usually pre-installed on Kali).

## 7. Validate ingestion

From the Wazuh dashboard → **Security Events**, confirm both agents show `active` and events are flowing (login events, file integrity checks, etc.). If nothing appears within a few minutes, check:
```bash
sudo tail -f /var/ossec/logs/ossec.log      # on manager
sudo /var/ossec/bin/agent_control -i <id>   # agent-specific status
```

## 8. Enable File Integrity Monitoring + rootcheck (used later for privesc detection)

Edit `/var/ossec/etc/ossec.conf` on the manager (or agent-side `ossec.conf` for per-agent scope):
```xml
<syscheck>
  <directories check_all="yes" realtime="yes">/etc,/bin,/sbin</directories>
  <directories check_all="yes" realtime="yes">C:\Windows\System32</directories>
</syscheck>
<rootcheck>
  <disabled>no</disabled>
</rootcheck>
```
Restart: `sudo systemctl restart wazuh-manager`.

Next: `02_detection_rules.md` for the custom brute-force/privesc rules and the tuning process.
