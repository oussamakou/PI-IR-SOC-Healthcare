import socket
import time
import sys

def simulate_ssh_attack(target_ip, port):
    print(f"[*] Attacking {target_ip}:{port} from 'WAN'...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((target_ip, port))
        print("[+] Connected! (Simulating TCP handshake)")
        
        # Simulate SSH version string exchange (Triggering Cowrie)
        try:
            banner = s.recv(1024)
            print(f"[+] Received banner: {banner.decode().strip()}")
            s.send(b"SSH-2.0-OpenSSH_8.2p1 AttackSim\r\n")
            time.sleep(1)
            # Send some junk to simulate login attempt
            s.send(b"root\n")
            s.send(b"password123\n")
        except Exception as e:
            print(f"[-] Data exchange failed (might be expected): {e}")

        s.close()
        print("[+] Attack finished. Check Wazuh logs for 'Cowrie' activity.")
    except Exception as e:
        print(f"[-] Attack failed: {e}")

if __name__ == "__main__":
    # 2222 is the mapped port for Cowrie in docker-compose.honeynet.yml
    target = "localhost" 
    port = 2222 
    simulate_ssh_attack(target, port)
