#!/bin/bash
# Setup Hospital Email Accounts

echo "Creating email accounts..."
docker exec mailserver setup email add doctor1@hospital.local password
docker exec mailserver setup email add doctor2@hospital.local password
docker exec mailserver setup email add admin@hospital.local password

echo "Accounts created:"
echo " - doctor1@hospital.local (password)"
echo " - doctor2@hospital.local (password)"
echo " - admin@hospital.local (password)"

echo "Configuration:"
echo " - SMTP: <HOST_IP>:25 (or 2526 if forwarded)"
echo " - IMAP: <HOST_IP>:143"
echo " - Username: full email address"
