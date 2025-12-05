#!/bin/bash
# Populate Hospital Data

echo "Waiting for Orthanc to be ready..."
until curl -s http://localhost:8042/instances > /dev/null; do
  echo "Orthanc is not ready yet. Retrying in 5s..."
  sleep 5
done

echo "Orthanc is UP. Downloading sample DICOM..."
# Download a sample CT scan DICOM file
curl -L -o sample.dcm https://github.com/orthanc-server/orthanc/raw/master/OrthancServer/Resources/Samples/CT-MONO2-16-ort.dcm

echo "Uploading DICOM to Orthanc..."
# Upload to Orthanc (using default admin:admin credentials)
curl -X POST -u admin:admin http://localhost:8042/instances --data-binary @sample.dcm

echo "DICOM Upload Complete."
echo "Check Orthanc at http://localhost:8042 to see the study."

echo ""
echo "--- OpenEMR Data Population ---"
echo "To populate OpenEMR with demo data:"
echo "1. Log in to OpenEMR (http://localhost:8085)"
echo "2. Go to Administration > System > Backup"
echo "3. Or use the Setup Wizard's 'Demo' option if you haven't completed setup yet."
echo "   (Note: Automated population requires a SQL dump which is not included in this repo)"
