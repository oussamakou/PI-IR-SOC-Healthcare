# DevSecOps Detection-as-Code - Academic Deliverables

## Overview

This document outlines the three key DevSecOps artifacts you'll deliver for academic grading, demonstrating modern security engineering practices within the team's SOC project.

## Artifact 1: Infrastructure-as-Code (Terraform)

### What It Demonstrates
- **Reproducibility**: Entire detection pipeline can be rebuilt from code
- **Version Control**: Infrastructure changes tracked in Git
- **Documentation**: Self-documenting infrastructure through code

### Deliverables

#### 1.1 Terraform Modules
```
terraform/
├── main.tf                    # Root module
├── modules/
│   ├── k3s-cluster/          # Kubernetes cluster setup
│   ├── detection-services/    # Sigma converter, ML API, connectors
│   ├── monitoring/            # Prometheus + Grafana
│   └── integrations/          # Wazuh, Shuffle, MISP connections
└── environments/
    ├── dev/                   # Development environment
    └── prod/                  # Production (for demo)
```

#### 1.2 Grading Criteria
| Criterion          | Weight | Evidence                                        |
| ------------------ | ------ | ----------------------------------------------- |
| **Code Quality**   | 25%    | Modular design, variables, outputs              |
| **Documentation**  | 20%    | README with architecture diagrams               |
| **Functionality**  | 30%    | `terraform apply` successfully deploys pipeline |
| **Best Practices** | 25%    | State management, secrets handling, versioning  |

#### 1.3 Demonstration
```bash
# Show professor:
cd terraform/
terraform init
terraform plan  # Shows what will be created
terraform apply -auto-approve  # Deploys entire pipeline in <5 minutes
kubectl get all -n detection-pipeline  # Verify all services running
```

---

## Artifact 2: Detection-as-Code Repository

### What It Demonstrates
- **Security-as-Code**: Detection rules version-controlled like application code
- **CI/CD for Security**: Automated testing and deployment of security rules
- **Collaboration**: Team can contribute rules via pull requests

### Deliverables

#### 2.1 Rule Library
```
detection-rules/
├── sigma/
│   ├── hipaa/
│   │   ├── unauthorized_phi_access.yml          # 164.308(a)(3)
│   │   ├── encryption_disabled.yml              # 164.312(a)(2)(iv)
│   │   └── audit_log_tampering.yml              # 164.312(b)
│   ├── hl7-attacks/
│   │   ├── hl7_message_injection.yml
│   │   ├── adt_flood.yml
│   │   └── malformed_hl7_segment.yml
│   ├── dicom-threats/
│   │   ├── unauthorized_dicom_query.yml
│   │   ├── dicom_port_scan.yml
│   │   └── pacs_data_exfiltration.yml
│   └── medical-device/
│       ├── iomt_anomaly.yml
│       └── infusion_pump_tampering.yml
├── yara/
│   ├── ransomware/
│   │   ├── ryuk_healthcare.yar
│   │   └── lockbit_medical.yar
│   └── medical-malware/
│       └── medjack_iot.yar
└── tests/
    ├── test_sigma_rules.py
    └── sample_logs/
```

**Minimum Deliverable**: 50 Sigma rules covering:
- 15 HIPAA compliance violations
- 15 Healthcare-specific attacks (HL7, DICOM)
- 10 Medical device security
- 10 General threats (ransomware, insider threats)

#### 2.2 CI/CD Pipeline
```yaml
# .github/workflows/detection-pipeline.yml
name: Detection-as-Code Pipeline

on: [push, pull_request]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - name: Validate Sigma Syntax
        run: sigma check sigma/**/*.yml
      
      - name: Run Unit Tests
        run: pytest tests/unit/
      
      - name: Convert to Wazuh Format
        run: sigma convert -t wazuh sigma/ -o converted/
      
      - name: Test Against Sample Logs
        run: pytest tests/integration/
  
  deploy:
    needs: validate
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    steps:
      - name: Deploy to k3s
        run: kubectl apply -f k8s-manifests/
      
      - name: Reload Wazuh Rules
        run: curl -X POST https://wazuh-api/rules/reload
```

#### 2.3 Grading Criteria
| Criterion                | Weight | Evidence                                          |
| ------------------------ | ------ | ------------------------------------------------- |
| **Rule Coverage**        | 30%    | 50+ rules covering healthcare threats             |
| **Rule Quality**         | 25%    | Accurate detection, low false positives           |
| **CI/CD Implementation** | 25%    | Automated testing and deployment                  |
| **Documentation**        | 20%    | Each rule has description, references, test cases |

#### 2.4 Demonstration
```bash
# Live demo for professor:
# 1. Create new Sigma rule
vim sigma/hipaa/new_rule.yml

# 2. Commit and push
git add sigma/hipaa/new_rule.yml
git commit -m "Add new HIPAA detection rule"
git push

# 3. Show GitHub Actions running tests
# Open browser to https://github.com/YOUR_REPO/actions

# 4. Show automatic deployment to k3s
kubectl logs -n argocd -l app.kubernetes.io/name=argocd-application-controller

# 5. Verify rule active in Wazuh
curl -u admin:admin https://wazuh-api/rules | jq '.data.items[] | select(.description | contains("new_rule"))'

# Total time: <2 minutes from commit to production
```

---

## Artifact 3: AI/ML Detection Engine

### What It Demonstrates
- **Machine Learning for Security**: Automated anomaly detection
- **Healthcare Context**: Models trained on medical workload patterns
- **MLOps**: Automated model training, deployment, monitoring

### Deliverables

#### 3.1 ML Models

| Model                       | Algorithm        | Purpose                                     | Training Data                 |
| --------------------------- | ---------------- | ------------------------------------------- | ----------------------------- |
| **Network Anomaly**         | Isolation Forest | Detect unusual HL7/DICOM traffic            | Zeek logs from Security Onion |
| **User Behavior Analytics** | LSTM             | Identify compromised medical staff accounts | Wazuh authentication logs     |
| **Medical Device Baseline** | Autoencoder      | Flag abnormal IoMT device behavior          | Device telemetry              |

#### 3.2 Model Training Pipeline
```python
# ml-detection/training/pipeline.py
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report
import mlflow

def train_network_anomaly_model():
    # 1. Load data from Zeek logs
    data = pd.read_csv('/data/zeek_conn.log')
    
    # 2. Feature engineering
    features = extract_features(data)
    
    # 3. Train model
    model = IsolationForest(contamination=0.1)
    model.fit(features)
    
    # 4. Evaluate
    predictions = model.predict(features)
    print(classification_report(labels, predictions))
    
    # 5. Log to MLflow
    mlflow.sklearn.log_model(model, "network_anomaly")
    
    # 6. Deploy to k8s
    deploy_model_to_k8s(model)

# Automated retraining every week
schedule.every().week.do(train_network_anomaly_model)
```

#### 3.3 Inference API
```python
# ml-detection/inference/api.py
from fastapi import FastAPI
from pydantic import BaseModel
import joblib

app = FastAPI()

class Alert(BaseModel):
    source_ip: str
    dest_ip: str
    port: int
    bytes_sent: int

@app.post("/predict")
async def predict(alert: Alert):
    model = joblib.load('/models/network_anomaly.pkl')
    features = [alert.port, alert.bytes_sent]
    
    prediction = model.predict([features])[0]
    confidence = model.predict_proba([features])[0][1]
    
    return {
        "is_anomaly": bool(prediction),
        "confidence": float(confidence),
        "model_version": "v1.2.0"
    }
```

#### 3.4 Grading Criteria
| Criterion                | Weight | Evidence                                   |
| ------------------------ | ------ | ------------------------------------------ |
| **Model Performance**    | 30%    | >85% accuracy, <15% false positives        |
| **Healthcare Relevance** | 25%    | Models trained on medical workload data    |
| **MLOps Pipeline**       | 25%    | Automated training, versioning, deployment |
| **Integration**          | 20%    | Real-time scoring of Wazuh alerts          |

#### 3.5 Demonstration
```bash
# Live demo for professor:
# 1. Show model training
cd ml-detection/training
python train_network_anomaly.py
# Output: Model accuracy: 92.3%, F1-score: 0.89

# 2. Show model deployment
kubectl get deployment ml-inference -n detection-pipeline
# Output: ml-inference   1/1     1            1           5m

# 3. Test inference API
curl -X POST http://ml-api:8000/predict \
  -H "Content-Type: application/json" \
  -d '{"source_ip":"192.168.60.100","dest_ip":"8.8.8.8","port":4444,"bytes_sent":100000}'
# Output: {"is_anomaly":true,"confidence":0.94,"model_version":"v1.2.0"}

# 4. Show integration with Wazuh
tail -f /var/log/wazuh-connector.log
# Output: [2025-12-12 10:30:45] Alert enriched with ML score: 0.94 → Forwarded to Shuffle

# 5. Show Grafana dashboard with ML metrics
# Open browser to http://grafana:3000/d/ml-detection
# Shows: Model accuracy over time, prediction latency, anomaly rate
```

---

## Integration with Team's SOC Project

### Your Role in Team Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Team's SOC Infrastructure                 │
│                                                              │
│  Aziz (Wazuh) ──→ YOUR DETECTION PIPELINE ──→ Your Shuffle  │
│       ↓                      ↓                      ↓        │
│  Yessine (Zeek) ──→    ML Enrichment    ──→  Dali (TheHive) │
│       ↓                      ↓                      ↓        │
│  Amine (MISP) ──→    Rule Updates      ──→  Salsabil (Graf) │
└─────────────────────────────────────────────────────────────┘
```

### Data Flow
1. **Aziz's Wazuh** generates raw alerts
2. **Your Detection Pipeline** enriches with:
   - Sigma rule matching
   - ML anomaly scoring
   - MISP threat intel (from Amine)
3. **Your Shuffle** receives high-confidence alerts
4. **Dali's TheHive** creates incident cases
5. **Salsabil's Grafana** displays detection metrics

### Team Benefits
- **Aziz**: Gets enhanced Wazuh rules from your Sigma repository
- **Yessine**: Your ML models consume his Zeek logs for training
- **Amine**: Your pipeline auto-updates rules with his MISP IoCs
- **Dali**: Receives pre-enriched alerts with ML confidence scores
- **Salsabil**: New dashboard showing detection pipeline performance

---

## Academic Presentation Structure

### Slide Deck Outline (15-20 minutes)

#### 1. Problem Statement (2 min)
- Traditional SOC: Manual rule creation, slow deployment
- Healthcare: Unique threats (HL7, DICOM, medical devices)
- Solution: DevSecOps approach to detection engineering

#### 2. Architecture Overview (3 min)
- Show Mermaid diagram from `DEVSECOPS_ARCHITECTURE.md`
- Explain k3s + Terraform + GitOps stack
- Highlight integration with team's infrastructure

#### 3. Artifact 1: Infrastructure-as-Code (3 min)
- Live demo: `terraform apply` → entire pipeline deployed
- Show modular design, state management
- Explain reproducibility benefits

#### 4. Artifact 2: Detection-as-Code (4 min)
- Show Sigma rule library (50+ rules)
- Live demo: Commit rule → CI/CD → Auto-deploy
- Show GitHub Actions pipeline
- Demonstrate rule testing framework

#### 5. Artifact 3: AI/ML Engine (4 min)
- Explain 3 ML models (network, UBA, device)
- Show training pipeline and MLflow tracking
- Live demo: Send alert → ML scoring → Shuffle
- Show Grafana dashboard with ML metrics

#### 6. Results & Impact (2 min)
- Detection coverage: 50+ healthcare-specific rules
- Automation: 100% GitOps deployment (zero manual)
- Performance: <5s alert enrichment, >90% ML accuracy
- Team value: Enhanced Wazuh, pre-enriched alerts

#### 7. Q&A (2 min)

### Live Demonstration Script

```bash
# Terminal 1: Infrastructure
cd terraform/
terraform apply -auto-approve  # Show automated deployment

# Terminal 2: Detection Rules
cd detection-rules/
vim sigma/demo/new_rule.yml  # Create rule live
git add . && git commit -m "Demo rule" && git push
# Show GitHub Actions running

# Terminal 3: ML Inference
curl -X POST http://ml-api:8000/predict -d @sample_alert.json
# Show anomaly detection result

# Terminal 4: Integration
tail -f /var/log/wazuh-connector.log
# Show real-time alert enrichment

# Browser: Grafana Dashboard
# Show detection metrics, ML performance, pipeline health
```

---

## Grading Rubric (Total: 100 points)

| Category                     | Points | Criteria                                                                                                     |
| ---------------------------- | ------ | ------------------------------------------------------------------------------------------------------------ |
| **Technical Implementation** | 40     | - Terraform deploys successfully (10)<br>- 50+ Sigma rules functional (15)<br>- ML models >85% accuracy (15) |
| **DevSecOps Practices**      | 25     | - GitOps workflow (10)<br>- CI/CD automation (10)<br>- Infrastructure-as-Code (5)                            |
| **Integration**              | 15     | - Connects to team's Wazuh (5)<br>- Enriches alerts to Shuffle (5)<br>- MISP threat intel sync (5)           |
| **Documentation**            | 10     | - Architecture diagrams (3)<br>- README files (3)<br>- Code comments (4)                                     |
| **Presentation**             | 10     | - Clear explanation (5)<br>- Live demo success (5)                                                           |

---

## Timeline Milestones

| Week   | Milestone               | Deliverable                        |
| ------ | ----------------------- | ---------------------------------- |
| **4**  | Infrastructure Complete | Terraform deploys k3s + ArgoCD     |
| **8**  | Detection Rules         | 50+ Sigma rules with CI/CD         |
| **12** | ML Engine               | 3 trained models deployed          |
| **16** | Integration             | Connected to team's Wazuh/Shuffle  |
| **20** | Testing                 | End-to-end attack simulations pass |
| **21** | Presentation            | Academic demo ready                |

---

## Success Metrics

### Quantitative
- ✅ 50+ Sigma rules covering healthcare threats
- ✅ 3 ML models with >85% accuracy
- ✅ <5 second alert enrichment latency
- ✅ 100% GitOps deployment (zero manual kubectl)
- ✅ >99% pipeline uptime

### Qualitative
- ✅ Team members use your Sigma rules in their Wazuh
- ✅ Professor can rebuild entire pipeline with `terraform apply`
- ✅ Live demo runs without errors
- ✅ Demonstrates all 5 DevSecOps principles
- ✅ Publishable as open-source project post-graduation

---

## Post-Graduation Value

### For Your Portfolio
- GitHub repo with 50+ security detection rules
- ML models for healthcare security
- Complete IaC for SOC pipeline
- Published blog post / conference talk

### For the Team
- Production-ready detection pipeline
- Reusable Terraform modules
- Healthcare-specific Sigma rule library
- ML model training framework

### For Future Students
- Template for SOC projects
- Detection-as-Code best practices
- Healthcare security research dataset
- Open-source contribution opportunity
