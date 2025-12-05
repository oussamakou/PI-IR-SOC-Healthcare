# Honeynet Zone Guide

## Overview
The Honeynet Zone is a set of decoy services designed to attract and detect attackers. It is isolated from the main Hospital LAN but monitored by the SOC.

## Services

### 1. Cowrie (SSH/Telnet Honeypot)
- **Port**: 2222 (SSH), 2223 (Telnet)
- **Role**: Simulates a vulnerable Linux server.
- **Usage**:
    - Attackers connect via `ssh -p 2222 root@<IP>`.
    - Cowrie logs their commands, downloads, and session data.
- **Logs**: stored in `cowrie_data` volume.

### 2. Dionaea (Malware Honeypot)
- **Ports**: SMB (445), FTP (21), HTTP (80), etc.
- **Role**: Simulates vulnerable Windows services to capture malware.
- **Usage**:
    - Passive listener. Detects network scans and exploit attempts.
- **Logs**: stored in `dionaea_data` volume.

### 3. Mailoney (SMTP Honeypot)
- **Port**: 2525 (Mapped to 25 on host via port forwarding)
- **Role**: Simulates an open SMTP relay or vulnerable mail server.
- **Usage**:
    - Attackers/Spammers connect to port 25 and try to send emails.
    - Mailoney logs the source IP, sender, recipient, and email content.
- **Logs**: stored in container logs (view with `docker logs honeynet-mailoney`).

## Log Flow & Monitoring

1.  **Generation**: Services generate logs in their containers.
2.  **Collection**:
    - **Velociraptor** can mount these log volumes to read them.
    - **Syslog**: Services can send logs to a central syslog (future improvement).
3.  **Detection**:
    - **Velociraptor Artifacts**:
        - `Custom.Honeynet.Cowrie.Sessions`: Parses Cowrie JSON logs.
        - `Custom.Honeynet.SMTP.Traffic`: Monitors Mailoney logs.

## Tasks for SOC Team

1.  **Monitor**: Watch Velociraptor for "Honeynet Activity" alerts.
2.  **Analyze**: When an alert triggers, investigate:
    - Source IP of the attacker.
    - Commands executed (Cowrie).
    - Malware dropped (Dionaea).
3.  **Hunt**: Correlate Honeynet hits with Hospital LAN traffic (did they pivot?).
