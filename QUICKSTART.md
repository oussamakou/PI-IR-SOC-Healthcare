# Detection-as-Code Pipeline - Quick Start Guide

## Prerequisites

### Hardware Setup
- ✅ Primary Workstation: i7-12th, 32GB RAM, 1TB SSD
- ✅ Proxmox Server: i7-8th, 16GB RAM, 1TB storage
- ✅ Network: Tailscale mesh configured with team

### Software Requirements
```powershell
# On Primary Workstation (Windows + WSL2)
wsl --install Ubuntu-22.04
wsl --set-version Ubuntu-22.04 2

# Inside WSL2
sudo apt update && sudo apt install -y \
    curl wget git vim \
    docker.io docker-compose \
    python3 python3-pip \
    terraform
```

## Phase 1: Infrastructure Setup (Week 1-2)

### Step 1: Install k3s

```bash
# In WSL2 on primary workstation
curl -sfL https://get.k3s.io | sh -

# Verify installation
sudo k3s kubectl get nodes

# Set up kubeconfig for non-root access
mkdir -p ~/.kube
sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
sudo chown $USER:$USER ~/.kube/config
export KUBECONFIG=~/.kube/config
```

### Step 2: Initialize Terraform

```bash
cd /mnt/c/hospital-lab
mkdir -p terraform

# Create main.tf
cat > terraform/main.tf <<'EOF'
terraform {
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.23"
    }
  }
}

provider "kubernetes" {
  config_path = "~/.kube/config"
}

# Namespace for detection pipeline
resource "kubernetes_namespace" "detection_pipeline" {
  metadata {
    name = "detection-pipeline"
  }
}
EOF

# Initialize and apply
cd terraform
terraform init
terraform plan
terraform apply -auto-approve
```

### Step 3: Deploy ArgoCD

```bash
# Create ArgoCD namespace
kubectl create namespace argocd

# Install ArgoCD
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml

# Wait for pods to be ready
kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=argocd-server -n argocd --timeout=300s

# Get admin password
kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d

# Port-forward to access UI
kubectl port-forward svc/argocd-server -n argocd 8080:443
# Access at https://localhost:8080 (username: admin)
```

## Phase 2: Detection Rules Repository (Week 3-4)

### Step 4: Create Detection Rules Repo

```bash
# Create new GitHub repo (do this on GitHub.com first)
# Then clone locally
cd /mnt/c/hospital-lab
git clone https://github.com/YOUR_USERNAME/detection-rules.git
cd detection-rules

# Create directory structure
mkdir -p sigma/{hipaa,hl7-attacks,dicom-threats,medical-device}
mkdir -p yara/{ransomware,medical-malware}
mkdir -p custom/{ml-models,behavioral}
mkdir -p tests/{unit,integration}
mkdir -p .github/workflows

# Create first Sigma rule
cat > sigma/hipaa/unauthorized_phi_access.yml <<'EOF'
title: Unauthorized PHI Access Attempt
id: 12345678-1234-1234-1234-123456789abc
status: experimental
description: Detects attempts to access Protected Health Information without proper authorization
author: Your Name
date: 2025/12/12
tags:
    - attack.credential_access
    - attack.t1078
    - hipaa.164.308
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: 'SYSCALL'
        syscall: 'open'
        key: 'phi_access'
    filter:
        auid: ['root', 'openemr', 'orthanc']
    condition: selection and not filter
falsepositives:
    - Legitimate administrative access
level: high
EOF

# Create CI/CD workflow
cat > .github/workflows/validate-sigma.yml <<'EOF'
name: Validate Sigma Rules

on:
  push:
    paths:
      - 'sigma/**/*.yml'
  pull_request:
    paths:
      - 'sigma/**/*.yml'

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      
      - name: Install sigma-cli
        run: pip install sigma-cli
      
      - name: Validate Sigma rules
        run: |
          for rule in sigma/**/*.yml; do
            echo "Validating $rule"
            sigma check $rule
          done
      
      - name: Convert to Wazuh format
        run: |
          mkdir -p converted/wazuh
          for rule in sigma/**/*.yml; do
            sigma convert -t wazuh $rule -o converted/wazuh/
          done
      
      - name: Upload artifacts
        uses: actions/upload-artifact@v3
        with:
          name: converted-rules
          path: converted/
EOF

# Commit and push
git add .
git commit -m "Initial detection rules structure"
git push origin main
```

### Step 5: Deploy Sigma Converter Service

```bash
cd /mnt/c/hospital-lab
mkdir -p k8s-manifests/detection-pipeline

cat > k8s-manifests/detection-pipeline/sigma-converter.yaml <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sigma-converter
  namespace: detection-pipeline
spec:
  replicas: 1
  selector:
    matchLabels:
      app: sigma-converter
  template:
    metadata:
      labels:
        app: sigma-converter
    spec:
      containers:
      - name: sigma-converter
        image: ghcr.io/sigmaHQ/sigma-cli:latest
        command: ["/bin/sh", "-c", "while true; do sleep 3600; done"]
        volumeMounts:
        - name: rules
          mountPath: /rules
      volumes:
      - name: rules
        emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: sigma-converter
  namespace: detection-pipeline
spec:
  selector:
    app: sigma-converter
  ports:
  - port: 8080
    targetPort: 8080
EOF

kubectl apply -f k8s-manifests/detection-pipeline/sigma-converter.yaml
```

## Phase 3: ML Detection Engine (Week 5-8)

### Step 6: Set Up ML Development Environment

```bash
cd /mnt/c/hospital-lab
mkdir -p ml-detection/{models,training,inference,deployment}

# Create requirements.txt
cat > ml-detection/requirements.txt <<'EOF'
fastapi==0.104.1
uvicorn==0.24.0
scikit-learn==1.3.2
pandas==2.1.3
numpy==1.26.2
joblib==1.3.2
prometheus-client==0.19.0
pydantic==2.5.0
EOF

# Create ML inference API
cat > ml-detection/inference/api.py <<'EOF'
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import joblib
import numpy as np
from prometheus_client import Counter, Histogram, generate_latest

app = FastAPI(title="ML Detection API")

# Metrics
PREDICTIONS = Counter('ml_predictions_total', 'Total predictions made')
ANOMALIES = Counter('ml_anomalies_detected', 'Anomalies detected')
LATENCY = Histogram('ml_inference_latency_seconds', 'Inference latency')

class Alert(BaseModel):
    source_ip: str
    dest_ip: str
    port: int
    protocol: str
    bytes_sent: int
    bytes_received: int

@app.post("/predict")
async def predict_anomaly(alert: Alert):
    with LATENCY.time():
        # Feature extraction
        features = np.array([[
            alert.port,
            alert.bytes_sent,
            alert.bytes_received
        ]])
        
        # Load model (in production, cache this)
        try:
            model = joblib.load('/models/network_anomaly.pkl')
        except FileNotFoundError:
            raise HTTPException(status_code=503, detail="Model not loaded")
        
        # Predict
        prediction = model.predict(features)[0]
        confidence = model.predict_proba(features)[0][1]
        
        PREDICTIONS.inc()
        if prediction == 1:
            ANOMALIES.inc()
        
        return {
            "is_anomaly": bool(prediction),
            "confidence": float(confidence),
            "alert": alert.dict()
        }

@app.get("/metrics")
async def metrics():
    return generate_latest()

@app.get("/health")
async def health():
    return {"status": "healthy"}
EOF

# Create Dockerfile
cat > ml-detection/deployment/Dockerfile <<'EOF'
FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY inference/ ./inference/
COPY models/ ./models/

EXPOSE 8000

CMD ["uvicorn", "inference.api:app", "--host", "0.0.0.0", "--port", "8000"]
EOF
```

### Step 7: Train Initial ML Model

```bash
# Create training script
cat > ml-detection/training/train_network_anomaly.py <<'EOF'
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
import joblib

# Generate synthetic training data (replace with real Zeek logs later)
np.random.seed(42)
normal_data = pd.DataFrame({
    'port': np.random.choice([80, 443, 22, 3389], 1000),
    'bytes_sent': np.random.normal(1000, 200, 1000),
    'bytes_received': np.random.normal(2000, 400, 1000)
})

anomaly_data = pd.DataFrame({
    'port': np.random.choice([4444, 1337, 31337], 100),
    'bytes_sent': np.random.normal(10000, 2000, 100),
    'bytes_received': np.random.normal(100, 20, 100)
})

# Combine and label
normal_data['label'] = 0
anomaly_data['label'] = 1
data = pd.concat([normal_data, anomaly_data])

# Train model
X = data[['port', 'bytes_sent', 'bytes_received']]
y = data['label']

model = IsolationForest(contamination=0.1, random_state=42)
model.fit(X)

# Save model
joblib.dump(model, '../models/network_anomaly.pkl')
print("Model trained and saved!")
EOF

# Run training
cd ml-detection/training
python3 train_network_anomaly.py
```

## Phase 4: Team Integration (Week 9-12)

### Step 8: Create Wazuh Connector

```bash
cd /mnt/c/hospital-lab
mkdir -p integrations/wazuh-connector

cat > integrations/wazuh-connector/main.py <<'EOF'
import requests
import time
import os
from datetime import datetime

WAZUH_API = os.getenv('WAZUH_API_URL', 'https://aziz-wazuh:55000')
WAZUH_USER = os.getenv('WAZUH_USER', 'admin')
WAZUH_PASS = os.getenv('WAZUH_PASS', 'admin')
ML_API = os.getenv('ML_API_URL', 'http://ml-inference:8000')
SHUFFLE_WEBHOOK = os.getenv('SHUFFLE_WEBHOOK_URL')

def get_wazuh_token():
    """Authenticate with Wazuh API"""
    response = requests.post(
        f"{WAZUH_API}/security/user/authenticate",
        auth=(WAZUH_USER, WAZUH_PASS),
        verify=False
    )
    return response.json()['data']['token']

def fetch_alerts(token, last_timestamp):
    """Fetch new alerts from Wazuh"""
    headers = {'Authorization': f'Bearer {token}'}
    params = {'timestamp': last_timestamp}
    
    response = requests.get(
        f"{WAZUH_API}/alerts",
        headers=headers,
        params=params,
        verify=False
    )
    return response.json()['data']['affected_items']

def enrich_with_ml(alert):
    """Send alert to ML API for scoring"""
    try:
        response = requests.post(
            f"{ML_API}/predict",
            json={
                'source_ip': alert.get('data', {}).get('srcip', ''),
                'dest_ip': alert.get('data', {}).get('dstip', ''),
                'port': alert.get('data', {}).get('dstport', 0),
                'protocol': alert.get('data', {}).get('protocol', ''),
                'bytes_sent': alert.get('data', {}).get('bytes_sent', 0),
                'bytes_received': alert.get('data', {}).get('bytes_received', 0)
            },
            timeout=5
        )
        return response.json()
    except Exception as e:
        print(f"ML enrichment failed: {e}")
        return None

def send_to_shuffle(enriched_alert):
    """Forward high-confidence alerts to Shuffle"""
    if enriched_alert and enriched_alert.get('confidence', 0) > 0.7:
        requests.post(SHUFFLE_WEBHOOK, json=enriched_alert)

def main():
    print("Starting Wazuh connector...")
    token = get_wazuh_token()
    last_timestamp = datetime.now().isoformat()
    
    while True:
        try:
            alerts = fetch_alerts(token, last_timestamp)
            
            for alert in alerts:
                ml_result = enrich_with_ml(alert)
                if ml_result:
                    enriched = {**alert, 'ml_score': ml_result}
                    send_to_shuffle(enriched)
            
            if alerts:
                last_timestamp = alerts[-1]['timestamp']
            
            time.sleep(30)  # Poll every 30 seconds
            
        except Exception as e:
            print(f"Error: {e}")
            token = get_wazuh_token()  # Refresh token
            time.sleep(60)

if __name__ == '__main__':
    main()
EOF
```

## Phase 5: Healthcare Workloads on Proxmox (Week 13-16)

### Step 9: Deploy OpenEMR VM

```bash
# SSH to Proxmox server
ssh root@proxmox-server

# Download OpenEMR cloud image
wget https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img

# Create VM
qm create 100 --name openemr --memory 4096 --cores 2 --net0 virtio,bridge=vmbr0
qm importdisk 100 jammy-server-cloudimg-amd64.img local-lvm
qm set 100 --scsihw virtio-scsi-pci --scsi0 local-lvm:vm-100-disk-0
qm set 100 --boot c --bootdisk scsi0
qm set 100 --agent enabled=1

# Start VM
qm start 100

# Install OpenEMR (after VM boots)
# SSH into VM and run:
docker run -d --name openemr \
  -p 80:80 -p 443:443 \
  -e MYSQL_ROOT_PASSWORD=root \
  openemr/openemr:latest

# Install Wazuh agent
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
apt update && apt install wazuh-agent

# Configure agent to point to Aziz's Wazuh manager
echo "WAZUH_MANAGER='aziz-wazuh-ip'" >> /var/ossec/etc/ossec.conf
systemctl restart wazuh-agent
```

## Phase 6: End-to-End Testing (Week 17-21)

### Step 10: Run Attack Simulation

```bash
# Create attack simulation script
cat > /mnt/c/hospital-lab/scripts/simulate-attack.sh <<'EOF'
#!/bin/bash

echo "Simulating healthcare-specific attacks..."

# 1. Unauthorized PHI access
ssh openemr-vm "cat /var/www/html/openemr/sites/default/documents/patient_*.pdf"

# 2. DICOM port scan
nmap -p 4242,11112 orthanc-vm

# 3. HL7 message injection
echo "MSH|^~\&|SIMULATOR|HOSPITAL|EMR|HOSPITAL|20251212||ADT^A01|123456|P|2.5" | nc openemr-vm 2575

# 4. Ransomware simulation (safe)
ssh openemr-vm "touch /tmp/.encrypted && echo 'Your files are encrypted' > /tmp/README.txt"

echo "Attack simulation complete. Check Wazuh → ML Pipeline → Shuffle for alerts!"
EOF

chmod +x scripts/simulate-attack.sh
./scripts/simulate-attack.sh
```

### Step 11: Verify Detection Pipeline

```bash
# Check k3s pods
kubectl get pods -n detection-pipeline

# Check ML API health
curl http://localhost:8000/health

# Check Wazuh connector logs
kubectl logs -n detection-pipeline -l app=wazuh-connector --tail=50

# Check Shuffle for new workflows triggered
# Access Shuffle UI and verify enriched alerts arrived
```

## Troubleshooting

### k3s won't start in WSL2
```bash
# Enable systemd in WSL2
echo -e "[boot]\nsystemd=true" | sudo tee -a /etc/wsl.conf
# Restart WSL from PowerShell: wsl --shutdown
```

### ArgoCD can't sync
```bash
# Check ArgoCD application status
kubectl get applications -n argocd
kubectl describe application detection-pipeline -n argocd
```

### ML API returns 503
```bash
# Ensure model file exists
kubectl exec -it -n detection-pipeline deployment/ml-inference -- ls /models/
# Retrain model if missing
```

### Wazuh connector can't authenticate
```bash
# Verify Tailscale connectivity
ping aziz-wazuh-ip
# Check credentials in k8s secret
kubectl get secret wazuh-creds -n detection-pipeline -o yaml
```

## Next Steps

1. ✅ Complete Phase 1-2 (Infrastructure + Detection Rules)
2. ⏳ Train ML models with real Zeek logs from Yessine
3. ⏳ Integrate with Amine's MISP for threat intel
4. ⏳ Create Grafana dashboard for detection metrics
5. ⏳ Document for academic presentation

## Resources

- [Sigma Rule Specification](https://github.com/SigmaHQ/sigma)
- [k3s Documentation](https://docs.k3s.io/)
- [ArgoCD Getting Started](https://argo-cd.readthedocs.io/)
- [Wazuh API Reference](https://documentation.wazuh.com/current/user-manual/api/reference.html)
- [Terraform Kubernetes Provider](https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs)
