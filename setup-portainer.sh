#!/bin/bash
# Deploy Portainer Standalone
# This keeps Portainer running even if you restart the main stack.

docker run -d \
  -p 9000:9000 \
  --name portainer \
  --restart always \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v portainer_data:/data \
  portainer/portainer-ce:latest

echo "Portainer started at http://localhost:9000"
