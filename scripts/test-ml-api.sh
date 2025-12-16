#!/bin/bash
# Test ML Inference API

set -e

API_URL="${1:-http://localhost:8000}"

echo "=== Testing ML Inference API ==="
echo "API URL: $API_URL"

# Test health endpoint
echo ""
echo "1. Testing /health endpoint..."
curl -s "$API_URL/health" | jq .

# Test prediction endpoint with normal traffic
echo ""
echo "2. Testing /predict with NORMAL traffic (HL7 port 2575)..."
curl -s -X POST "$API_URL/predict" \
  -H "Content-Type: application/json" \
  -d '{
    "source_ip": "192.168.60.10",
    "dest_ip": "192.168.60.11",
    "port": 2575,
    "protocol": "tcp",
    "bytes_sent": 5000,
    "bytes_received": 10000
  }' | jq .

# Test prediction endpoint with anomalous traffic
echo ""
echo "3. Testing /predict with ANOMALOUS traffic (C2 port 4444)..."
curl -s -X POST "$API_URL/predict" \
  -H "Content-Type: application/json" \
  -d '{
    "source_ip": "192.168.60.100",
    "dest_ip": "8.8.8.8",
    "port": 4444,
    "protocol": "tcp",
    "bytes_sent": 50000,
    "bytes_received": 500
  }' | jq .

# Test metrics endpoint
echo ""
echo "4. Testing /metrics endpoint..."
curl -s "$API_URL/metrics" | grep "ml_predictions_total"

echo ""
echo "=== ML API Tests Complete ==="
