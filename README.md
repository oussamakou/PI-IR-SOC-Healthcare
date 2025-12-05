# Production Deployment README

## Overview

This directory contains a production-ready hospital data center deployment with separated zones for security:

- **Internal Hospital**: OpenEMR (EMR) and Orthanc (PACS).
- **DMZ**: Patient Portal with Nginx Reverse Proxy.
- **Honeynet**: Deception services (Cowrie, Dionaea, Mailhog).

## Quick Start

### 1. Prerequisites

```bash
# Install Docker and Docker Compose
# Ensure WSL2 is configured with sufficient resources:
# - CPU: 4+ cores
# - RAM: 8+ GB
# - Disk: 100+ GB
```

### 2. Initial Setup

```bash
# Clone or navigate to hospital-lab directory
cd /mnt/c/hospital-lab

# Copy environment template
cp .env.example .env

# Edit .env and set all passwords
nano .env

# Start All Services (Hospital, DMZ, Honeynet)
docker-compose -f docker-compose.hospital.yml up -d
docker-compose -f docker-compose.dmz.yml up -d
docker-compose -f docker-compose.honeynet.yml up -d
```

### 3. Access Services

| Zone         | Service        | URL                   | Ports     | Notes                      |
| ------------ | -------------- | --------------------- | --------- | -------------------------- |
| **Hospital** | OpenEMR        | http://localhost:8085 | 8085:80   | Internal EMR System        |
| **Hospital** | Orthanc        | http://localhost:8042 | 8042:8042 | PACS System                |
| **DMZ**      | Patient Portal | http://localhost:8088 | 8088:80   | Public Web App (via Nginx) |
| **Honeynet** | Cowrie         | -                     | 2222:2222 | SSH Honeypot               |
| **Honeynet** | Mailhog        | http://localhost:8025 | 8025:8025 | SMTP Honeypot UI           |

## Network Architecture

The environment is segmented into three distinct networks to mimic a real-world secure topology.

### 1. Hospital Network (`hospitalnet`)
- **Subnet**: `192.168.60.0/24`
- **Purpose**: Secure internal network for sensitive medical data.
- **Services**: OpenEMR, MariaDB, Orthanc.

### 2. DMZ Network (`dmz_net`)
- **Subnet**: `192.168.20.0/24`
- **Purpose**: Semi-trusted network for public-facing services.
- **Services**: Patient Portal, Nginx Reverse Proxy.
- **Routing**: Should be configured in Pfsense to allow restricted access to/from WAN and LAN.

### 3. Honeynet (`honeynet`)
- **Subnet**: `192.168.122.0/24`
- **Purpose**: Trap network for detecting intruders.
- **Services**: Cowrie, Dionaea, Mailhog.

## File Structure

```
hospital-lab/
├── docker-compose.hospital.yml     # Internal Hospital Services
├── docker-compose.dmz.yml          # DMZ Services
├── docker-compose.honeynet.yml     # Honeynet Services
├── docker-compose.old.yml          # Archived monolithic config
├── ...
├── dmz/                            # DMZ Configuration
│   └── nginx/nginx.conf
├── patient-portal/                 # Patient Portal App
│   ├── Dockerfile                  # Gunicorn-based build
│   └── ...
└── ...
```

## Management

```bash
# View all running containers
docker ps

# Stop a specific stack
docker-compose -f docker-compose.dmz.yml down

# Rebuild a specific stack
docker-compose -f docker-compose.hospital.yml up -d --build
```

## Security & Pfsense

This setup is designed to work with a Pfsense firewall.
- **Gateways**: Configure your Pfsense interfaces to match the subnets above.
- **Rules**:
    - Block `honeynet` from accessing `hospitalnet`.
    - Allow `dmz_net` to access specific public IPs or restricted internal APIs (if needed).
    - Monitor traffic from `honeynet` using Velociraptor or logs.

## Version
- **Last Updated**: 2025-12-05
- **Architecture**: Separated Zones (LAN/DMZ/Honey)
