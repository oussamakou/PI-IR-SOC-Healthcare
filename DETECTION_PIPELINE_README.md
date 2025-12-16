# Detection-as-Code DevSecOps Pipeline

## Quick Setup

### Prerequisites
```bash
# Ensure WSL2 is running
wsl --list --verbose

# Start WSL
wsl
```

### 1. Install k3s
```bash
cd /mnt/c/hospital-lab
./scripts/install-k3s.sh
```

### 2. Train ML Model
```bash
cd ml-detection/training
python3 train_network_anomaly.py
```

### 3. Deploy Infrastructure with Terraform
```bash
cd terraform

# Update terraform.tfvars with team's endpoints
# - wazuh_api_url (from Aziz)
# - shuffle_webhook_url (your Shuffle instance)
# - misp_api_url (from Amine)

terraform init
terraform plan
terraform apply
```

### 4. Verify Deployment
```bash
# Check all pods are running
kubectl get pods -n detection-pipeline
kubectl get pods -n monitoring

# Check services
kubectl get svc -n detection-pipeline
kubectl get svc -n monitoring
```

### 5. Access Services
```bash
# Port-forward Grafana
kubectl port-forward -n monitoring svc/grafana 3000:3000
# Access at http://localhost:3000 (admin/admin)

# Port-forward ML API
kubectl port-forward -n detection-pipeline svc/ml-inference 8000:8000
# Test at http://localhost:8000/docs
```

## Architecture

```
┌─────────────────────────────────────────────┐
│         Detection Pipeline (k3s)            │
│                                             │
│  ┌──────────────┐  ┌──────────────┐       │
│  │   Wazuh      │  │  ML Inference│       │
│  │  Connector   │→ │     API      │       │
│  └──────────────┘  └──────────────┘       │
│         ↓                  ↓               │
│  ┌──────────────────────────────┐         │
│  │    Shuffle Webhook           │         │
│  └──────────────────────────────┘         │
└─────────────────────────────────────────────┘
         ↑                    ↓
    [Aziz's Wazuh]      [Your Shuffle]
```

## Components

- **Terraform**: Infrastructure-as-Code for k3s cluster
- **Wazuh Connector**: Pulls alerts from team's Wazuh Manager
- **ML Inference API**: Real-time anomaly detection
- **Sigma Converter**: Detection rules as code
- **Prometheus + Grafana**: Monitoring and metrics

## Next Steps

1. ✅ Infrastructure deployed
2. ⏳ Create Sigma rules repository
3. ⏳ Set up GitOps with ArgoCD
4. ⏳ Integrate with team's infrastructure
5. ⏳ Run attack simulations

## Documentation

- [Architecture](DEVSECOPS_ARCHITECTURE.md)
- [Quick Start](QUICKSTART.md)
- [Academic Deliverables](ACADEMIC_DELIVERABLES.md)
- [Implementation Plan](C:\Users\oussa\.gemini\antigravity\brain\c9eca323-9ad0-43a5-be2a-87cae433850a\implementation_plan.md)
