$remoteport = bash.exe -c "ifconfig eth0 | grep 'inet ' | awk '{print `$2}'"
$found = $remoteport -match '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}';

if( $found ){
  $remoteport = $matches[0];
} else{
  echo "The Script Exited, the ip address of WSL 2 cannot be found";
  exit;
}

# Ports to forward:
# 8085: OpenEMR (Changed from 8080 due to conflict)
# 8042: Orthanc
# 8888: Velociraptor
# 9000: Portainer
# 5000: Patient Portal
# 2525: Mailhog SMTP (Decoy)
# 8025: Mailhog UI (Decoy)
# 25: Hospital SMTP (Legitimate)
# 143: Hospital IMAP (Legitimate)
# 2222: Cowrie SSH
# 2223: Cowrie Telnet
$ports=@(8085, 8042, 8888, 9000, 5000, 2525, 8025, 25, 143, 2222, 2223);

$addr='0.0.0.0';
$ports | ForEach-Object -Process {
  if( $_ -eq 2525 ) {
    # Mailhog SMTP (Forward 25 on host to 2525 on WSL if possible, but 25 is likely taken. Using 2525->2525)
    iex "netsh interface portproxy delete v4tov4 listenport=2525 listenaddress=$addr";
    iex "netsh interface portproxy add v4tov4 listenport=2525 listenaddress=$addr connectport=2525 connectaddress=$remoteport";
  } elseif( $_ -eq 8025 ) {
    # Mailhog UI
    iex "netsh interface portproxy delete v4tov4 listenport=8025 listenaddress=$addr";
    iex "netsh interface portproxy add v4tov4 listenport=8025 listenaddress=$addr connectport=8025 connectaddress=$remoteport";
  } elseif( $_ -eq 25 ) {
    # Hospital SMTP (Forward 2526 on host to 25 on WSL to avoid Windows port 25 conflict)
    iex "netsh interface portproxy delete v4tov4 listenport=2526 listenaddress=$addr";
    iex "netsh interface portproxy add v4tov4 listenport=2526 listenaddress=$addr connectport=25 connectaddress=$remoteport";
  } else {
    iex "netsh interface portproxy delete v4tov4 listenport=$_ listenaddress=$addr";
    iex "netsh interface portproxy add v4tov4 listenport=$_ listenaddress=$addr connectport=$_ connectaddress=$remoteport";
  }
}

echo "Ports forwarded to WSL2 IP: $remoteport";
echo "Services Exposed:";
echo " - OpenEMR: http://<HOST_IP>:8080";
echo " - Orthanc: http://<HOST_IP>:8042";
echo " - Velociraptor: https://<HOST_IP>:8888";
echo " - Portainer: http://<HOST_IP>:9000";
echo " - Patient Portal: http://<HOST_IP>:5000";
echo " - GoPhish Admin: https://<HOST_IP>:3333";
echo " - GoPhish Page: http://<HOST_IP>:8081";
echo " - Cowrie SSH: ssh -p 2222 <HOST_IP>";
