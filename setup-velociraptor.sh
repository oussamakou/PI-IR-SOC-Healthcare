#!/bin/bash
# Velociraptor Server Setup Script for Hospital Lab Environment
# This script initializes Velociraptor configuration for the first time

set -e

echo "=========================================="
echo "Velociraptor Hospital Lab Setup"
echo "=========================================="

# Configuration directory
CONFIG_DIR="./velociraptor-config"
mkdir -p "$CONFIG_DIR"

echo ""
echo "[1/5] Generating Velociraptor server configuration..."

# Generate server configuration using Velociraptor's config generator
docker run --rm \
  -v "$(pwd)/$CONFIG_DIR:/config" \
  wlambert/velociraptor:latest \
  config generate \
  --config /config/server.config.yaml \
  --client /config/client.config.yaml \
  --api /config/api.config.yaml

echo "✓ Configuration files generated"

echo ""
echo "[2/5] Updating server configuration for hospital environment..."

# Update server config with hospital-specific settings
cat >> "$CONFIG_DIR/server.config.yaml" << 'EOF'

# Hospital Lab Customizations
logging:
  output_directory: /logs
  separate_logs_per_component: true
  
datastore:
  implementation: FileBaseDataStore
  location: /data
  filestore_directory: /data/filestore

# HIPAA Compliance Settings
audit:
  enabled: true
  log_all_queries: true
  
EOF

echo "✓ Server configuration updated"

echo ""
echo "[3/5] Creating custom hospital monitoring artifacts..."

# Create artifacts directory
ARTIFACTS_DIR="./velociraptor-artifacts"
mkdir -p "$ARTIFACTS_DIR"

# Docker Container Monitoring Artifact
cat > "$ARTIFACTS_DIR/Docker.Container.Monitoring.yaml" << 'EOF'
name: Custom.Docker.Container.Monitoring
description: Monitor Docker container health and resource usage for hospital services
author: Hospital Lab Security Team
type: CLIENT

sources:
  - precondition:
      SELECT OS From info() where OS = 'linux'
    
    query: |
      LET containers = SELECT * FROM execve(
        argv=["docker", "ps", "--format", "{{.ID}}|{{.Names}}|{{.Status}}|{{.Image}}"]
      )
      
      SELECT parse_string_with_regex(
        string=Stdout,
        regex="(?P<ContainerID>[^|]+)\\|(?P<Name>[^|]+)\\|(?P<Status>[^|]+)\\|(?P<Image>.+)"
      ) AS ContainerInfo
      FROM containers
      WHERE Stdout =~ "openemr|orthanc|mariadb"

reports:
  - type: CLIENT
    template: |
      # Hospital Container Health Report
      
      {{ range .Rows }}
      - **{{ .ContainerInfo.Name }}**: {{ .ContainerInfo.Status }}
      {{ end }}
EOF

# HIPAA File Access Audit Artifact
cat > "$ARTIFACTS_DIR/HIPAA.FileAccess.Audit.yaml" << 'EOF'
name: Custom.HIPAA.FileAccess.Audit
description: Audit file access to sensitive medical data directories
author: Hospital Lab Security Team
type: CLIENT_EVENT

sources:
  - query: |
      SELECT * FROM watch_monitoring(
        paths=[
          "/monitor/openemr/**",
          "/monitor/orthanc/**"
        ]
      )
      WHERE Name =~ "\\.(php|sql|dcm|xml|json)$"

reports:
  - type: CLIENT_EVENT
    template: |
      # HIPAA File Access Alert
      
      **File**: {{ .FullPath }}
      **Action**: {{ .Action }}
      **Timestamp**: {{ .Timestamp }}
      **User**: {{ .User }}
EOF

# PACS DICOM Traffic Monitoring
cat > "$ARTIFACTS_DIR/PACS.DICOM.Traffic.yaml" << 'EOF'
name: Custom.PACS.DICOM.Traffic
description: Monitor DICOM network traffic to Orthanc PACS
author: Hospital Lab Security Team
type: CLIENT_EVENT

sources:
  - query: |
      SELECT * FROM watch_monitoring(
        paths=["/monitor/orthanc_logs/**"]
      )
      WHERE Data =~ "DICOM|C-STORE|C-FIND|C-MOVE"

reports:
  - type: CLIENT_EVENT
    template: |
      # DICOM Traffic Alert
      
      **Log File**: {{ .Name }}
      **Content**: {{ .Data }}
      **Timestamp**: {{ .Timestamp }}
EOF

echo "✓ Custom artifacts created in $ARTIFACTS_DIR/"

echo ""
echo "[4/5] Creating initial admin user..."

# Note: Admin user will be created on first GUI login
cat > "$CONFIG_DIR/INITIAL_SETUP.txt" << 'EOF'
VELOCIRAPTOR INITIAL SETUP INSTRUCTIONS
========================================

1. Start the containers:
   docker-compose up -d

2. Access the Velociraptor GUI:
   https://localhost:8000

3. On first access, you'll be prompted to create an admin user.
   Recommended username: admin
   Use a strong password (minimum 12 characters)

4. After login, import custom artifacts:
   - Navigate to: View Artifacts > Upload Artifact
   - Upload files from ./velociraptor-artifacts/

5. Deploy agent on WSL2 host:
   - Download client config: Server Artifacts > Client Config
   - Install agent: 
     sudo dpkg -i velociraptor-client.deb
     sudo systemctl enable velociraptor-client
     sudo systemctl start velociraptor-client

6. Verify agent connection:
   - Navigate to: Show All > Clients
   - You should see your WSL2 host listed

SECURITY NOTES:
- Change default passwords for OpenEMR and Orthanc
- Enable TLS for production deployment
- Regularly review audit logs
- Keep all containers updated

For production deployment, see HOSPITAL_DEPLOYMENT.md
EOF

echo "✓ Setup instructions created: $CONFIG_DIR/INITIAL_SETUP.txt"

echo ""
echo "[5/5] Setting proper permissions..."
chmod -R 755 "$CONFIG_DIR"
chmod -R 755 "$ARTIFACTS_DIR"

echo "✓ Permissions set"

echo ""
echo "=========================================="
echo "✓ Velociraptor setup complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "1. Review configuration in $CONFIG_DIR/"
echo "2. Start containers: docker-compose up -d"
echo "3. Access GUI: https://localhost:8000"
echo "4. Follow instructions in $CONFIG_DIR/INITIAL_SETUP.txt"
echo ""
echo "Custom artifacts location: $ARTIFACTS_DIR/"
echo ""
