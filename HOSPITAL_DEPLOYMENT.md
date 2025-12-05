# Hospital Data Center Deployment Guide

## Overview

This guide explains how to deploy and use the containerized hospital lab environment as a data center for medical imaging (PACS) and electronic medical records (EMR) with endpoint detection and response (EDR) monitoring.

## Architecture

```mermaid
graph TB
    subgraph "Hospital Data Center"
        subgraph "Clinical Systems"
            EMR[OpenEMR<br/>EMR System<br/>:8080]
            PACS[Orthanc<br/>PACS Server<br/>:8042]
            DB[(MariaDB<br/>Database)]
        end
        
        subgraph "Security Layer"
            EDR[Velociraptor<br/>EDR Server<br/>:8000]
            Agent[Velociraptor<br/>Agent]
        end
# Download client config from Velociraptor GUI
# Then install:
sudo dpkg -i velociraptor-client.deb
sudo systemctl enable velociraptor-client
sudo systemctl start velociraptor-client
#### Patient Registration
1. Navigate to **Patient/Client** > **New/Search**
2. Enter patient demographics
3. Assign medical record number (MRN)
4. Set insurance information

#### Clinical Documentation
1. Select patient from dashboard
2. Navigate to **Encounter** > **New Encounter**
3. Document:
   - Chief complaint
   - Vital signs
   - History and physical
   - Assessment and plan
4. Sign and lock encounter

#### Prescription Management
1. In patient encounter
2. Navigate to **Prescriptions**
3. Search medication
4. Set dosage, frequency, duration
5. Print or send electronically

#### Lab Orders Integration
1. Order labs through encounter
2. Results can be imported via HL7
3. Review in **Reports** section

### Integration with PACS

OpenEMR can link to Orthanc PACS for viewing medical images:

1. **Configure PACS Link**:
   - Administration > Globals > Connectors
   - Set Orthanc URL: `http://orthanc:8042`
   - Enable DICOM viewer

2. **View Images**:
   - In patient chart, click **Imaging**
   - Images from Orthanc display inline
   - Launch DICOM viewer for advanced tools

# Via Orthanc configuration or GUI
# Example: Adding a CT scanner
{
  "DicomModalities": {
    "CT_SCANNER_1": {
      "AET": "CT1",
      "Host": "192.168.1.100",
      "Port": 104
    }
  }
}
```

### Receiving DICOM Images

#### From Modality (Push)
1. Configure modality to send to:
   - AET: `ORTHANC`
   - Host: `<server-ip>`
   - Port: `4242`

2. Images appear automatically in Orthanc

#### Manual Upload
1. Navigate to **Upload** in Orthanc GUI
2. Select DICOM files (.dcm)
3. Upload completes automatically

### Querying and Retrieving Images

#### C-FIND (Query)
```bash
# Query for patient studies
curl -X POST http://localhost:8042/modalities/CT_SCANNER_1/query \
  -d '{"Level":"Study","Query":{"PatientID":"12345"}}'
```

#### C-MOVE (Retrieve)
```bash
# Retrieve study to Orthanc
curl -X POST http://localhost:8042/modalities/CT_SCANNER_1/move \
  -d '{"Level":"Study","Resources":["study-uuid"]}'
```

### DICOM Web (DICOMweb)

Orthanc supports modern DICOMweb protocols:
- **WADO-RS**: Retrieve images via HTTP
- **QIDO-RS**: Query for studies
- **STOW-RS**: Store images

---

## Velociraptor Monitoring

### Custom Hospital Artifacts

Three custom artifacts are included for hospital-specific monitoring:

#### 1. Docker Container Monitoring
**Artifact**: `Custom.Docker.Container.Monitoring`

Monitors health of hospital containers:
- OpenEMR uptime
- Orthanc availability  
- Database connectivity

**Usage**:
1. Navigate to **Hunt Manager**
2. Create new hunt
3. Select artifact
4. Schedule: Every 5 minutes

#### 2. HIPAA File Access Audit
**Artifact**: `Custom.HIPAA.FileAccess.Audit`

Tracks access to sensitive medical data:
- Patient records
- Medical images
- Database files

**Compliance**: Required for HIPAA audit trail

#### 3. PACS DICOM Traffic
**Artifact**: `Custom.PACS.DICOM.Traffic`

Monitors DICOM operations:
- C-STORE (image storage)
- C-FIND (queries)
- C-MOVE (retrievals)

**Security**: Detects unauthorized DICOM access

### Setting Up Alerts

```yaml
# Example: Alert on failed login attempts
name: Custom.Hospital.FailedLogins
sources:
  - query: |
      SELECT * FROM watch_monitoring(
        paths=["/monitor/openemr_logs/**"]
      )
      WHERE Data =~ "Failed login|Authentication failed"
      
actions:
  - type: email
    to: security@hospital.local
    subject: "Failed Login Detected"
```

---

## Security & Compliance

### HIPAA Requirements

| Requirement           | Implementation                        |
| --------------------- | ------------------------------------- |
| **Access Control**    | User authentication on all systems    |
| **Audit Logging**     | Velociraptor tracks all file access   |
| **Data Encryption**   | Enable TLS for production (see below) |
| **Backup & Recovery** | Daily backups to external storage     |
| **Physical Security** | Secure server room access             |

### Enabling TLS/SSL

For production, enable HTTPS:

```yaml
# docker-compose.prod.yml
services:
  openemr:
    environment:
      - FORCE_HTTPS=true
    volumes:
      - ./certs/openemr.crt:/etc/ssl/certs/openemr.crt
      - ./certs/openemr.key:/etc/ssl/private/openemr.key
```

Generate certificates:
```bash
# Self-signed (development)
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout openemr.key -out openemr.crt

# Production: Use Let's Encrypt or hospital CA
```

### Password Policy

**Minimum Requirements**:
- Length: 12 characters
- Complexity: Upper, lower, number, special
- Rotation: Every 90 days
- History: Cannot reuse last 5 passwords

**Change Default Passwords**:
```bash
# OpenEMR: Via GUI (Administration > Users)
# Orthanc: Edit configuration file
# MariaDB: 
docker-compose exec openemr-db mysql -u root -p
ALTER USER 'root'@'%' IDENTIFIED BY 'new_strong_password';
```

---

## Backup & Disaster Recovery

### Automated Backups

```bash
#!/bin/bash
# backup-hospital-data.sh

BACKUP_DIR="/backups/$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

# Backup databases
docker-compose exec -T openemr-db mysqldump -u root -p$MYSQL_ROOT_PASSWORD --all-databases > "$BACKUP_DIR/databases.sql"

# Backup volumes
docker run --rm -v openemr_data:/data -v "$BACKUP_DIR":/backup alpine tar czf /backup/openemr_data.tar.gz -C /data .
docker run --rm -v orthanc_data:/data -v "$BACKUP_DIR":/backup alpine tar czf /backup/orthanc_data.tar.gz -C /data .
docker run --rm -v velociraptor_data:/data -v "$BACKUP_DIR":/backup alpine tar czf /backup/velociraptor_data.tar.gz -C /data .

# Encrypt backups (HIPAA requirement)
gpg --encrypt --recipient hospital-backup@hospital.local "$BACKUP_DIR"/*

echo "Backup completed: $BACKUP_DIR"
```

Schedule with cron:
```bash
# Daily at 2 AM
0 2 * * * /path/to/backup-hospital-data.sh
```

### Disaster Recovery

**Recovery Time Objective (RTO)**: 4 hours  
**Recovery Point Objective (RPO)**: 24 hours

**Recovery Steps**:
1. Restore docker-compose.yml
2. Restore volumes from backup
3. Start containers
4. Verify data integrity
5. Test all services

---

## Operational Procedures

### Daily Health Checks

```bash
# Check container status
docker-compose ps

# Check logs for errors
docker-compose logs --tail=100 openemr | grep -i error
docker-compose logs --tail=100 orthanc | grep -i error

# Check disk space
df -h

# Verify Velociraptor agent connectivity
# Via GUI: Show All > Clients
```

### Performance Monitoring

**Key Metrics**:
- CPU usage per container
- Memory consumption
- Disk I/O
- Network throughput
- Database query performance

**Tools**:
```bash
# Resource usage
docker stats

# Database performance
docker-compose exec openemr-db mysql -u root -p -e "SHOW PROCESSLIST;"
```

### Scaling for Increased Load

**Horizontal Scaling**:
```yaml
# docker-compose.scale.yml
services:
  openemr:
    deploy:
      replicas: 3
    
  orthanc:
    deploy:
      replicas: 2
```

**Load Balancer** (nginx):
```nginx
upstream openemr_backend {
    server openemr-1:80;
    server openemr-2:80;
    server openemr-3:80;
}
```

---

## Troubleshooting

### Common Issues

#### OpenEMR Not Accessible
```bash
# Check container status
docker-compose ps openemr

# Check logs
docker-compose logs openemr

# Restart service
docker-compose restart openemr
```

#### Orthanc Not Receiving DICOM
```bash
# Verify DICOM port is open
netstat -an | grep 4242

# Check Orthanc logs
docker-compose logs orthanc | grep DICOM

# Test DICOM connectivity
echoscu <orthanc-ip> 4242 -aec ORTHANC
```

#### Database Connection Errors
```bash
# Verify database is running
docker-compose ps openemr-db

# Test connection
docker-compose exec openemr-db mysql -u openemr -p openemr

# Check network
docker network inspect hospitalnet
```

#### Velociraptor Agent Not Connecting
```bash
# Check agent status
sudo systemctl status velociraptor-client

# View agent logs
sudo journalctl -u velociraptor-client -f

# Verify network connectivity
telnet <velociraptor-server-ip> 8001
```

---

## Production Deployment Checklist

- [ ] Change all default passwords
- [ ] Enable TLS/SSL on all services
- [ ] Configure firewall rules
- [ ] Set up automated backups
- [ ] Test disaster recovery procedure
- [ ] Configure log rotation
- [ ] Enable audit logging
- [ ] Set up monitoring alerts
- [ ] Document network topology
- [ ] Train staff on systems
- [ ] Perform security audit
- [ ] Obtain HIPAA compliance certification
- [ ] Set up redundant systems (HA)
- [ ] Configure VPN for remote access
- [ ] Implement intrusion detection

---

## Support & Resources

### Documentation
- **OpenEMR**: https://www.open-emr.org/wiki/
- **Orthanc**: https://book.orthanc-server.com/
- **Velociraptor**: https://docs.velociraptor.app/

### Community
- **OpenEMR Forums**: https://community.open-emr.org/
- **Orthanc Discourse**: https://discourse.orthanc-server.com/
- **Velociraptor Slack**: https://www.velocidex.com/slack

### Emergency Contacts
- **System Administrator**: [Contact Info]
- **Security Team**: [Contact Info]
- **Vendor Support**: [Contact Info]

---

## Appendix

### A. DICOM Basics

**DICOM** (Digital Imaging and Communications in Medicine) is the standard for medical imaging.

**Key Concepts**:
- **AET (Application Entity Title)**: Unique identifier for DICOM devices
- **C-STORE**: Send images to PACS
- **C-FIND**: Query for images
- **C-MOVE**: Retrieve images from PACS
- **C-ECHO**: Test connectivity

### B. HL7 Integration

**HL7** (Health Level 7) is the standard for clinical data exchange.

**Common Messages**:
- **ADT**: Patient admission/discharge/transfer
- **ORM**: Order messages (lab, imaging)
- **ORU**: Results (lab results)

### C. Network Ports Reference

| Service      | Port | Protocol | Purpose             |
| ------------ | ---- | -------- | ------------------- |
| OpenEMR      | 8080 | HTTP     | Web interface       |
| Orthanc      | 8042 | HTTP     | Web interface       |
| Orthanc      | 4242 | DICOM    | DICOM communication |
| MariaDB      | 3306 | MySQL    | Database            |
| Velociraptor | 8888 | HTTPS    | GUI                 |
| Velociraptor | 8001 | HTTPS    | Agent communication |

---

*Last Updated: 2025-12-03*  
*Version: 1.0*
