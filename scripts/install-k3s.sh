#!/bin/bash
# Install k3s on WSL2 for Detection-as-Code Pipeline

set -e

echo "=== Installing k3s on WSL2 ==="

# Check if running in WSL
if ! grep -qi microsoft /proc/version; then
    echo "Error: This script must run in WSL2"
    exit 1
fi

# Install k3s
echo "Installing k3s..."
curl -sfL https://get.k3s.io | sh -s - --write-kubeconfig-mode 644

# Wait for k3s to be ready
echo "Waiting for k3s to be ready..."
sleep 10

# Set up kubeconfig
mkdir -p ~/.kube
sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
sudo chown $USER:$USER ~/.kube/config
export KUBECONFIG=~/.kube/config

# Verify installation
echo "Verifying k3s installation..."
sudo k3s kubectl get nodes

echo ""
echo "=== k3s Installation Complete ==="
echo "Add this to your ~/.bashrc:"
echo "export KUBECONFIG=~/.kube/config"
echo ""
echo "Then run: source ~/.bashrc"
