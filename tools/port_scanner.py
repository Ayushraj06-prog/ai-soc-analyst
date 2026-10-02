import socket
from models.alert import Alert
from app.config import settings

class PortScanner:
    """
    A beginner-friendly, defensive Port Scanner.
    
    EDUCATIONAL CONCEPT:
    - What is a Port? Think of an IP address as an apartment building, and ports as 
      the individual apartment numbers. Services (like a web server or email server) 
      "live" in specific apartments.
    - What is a Socket? A socket is the software endpoint that establishes a network 
      connection between your computer and the target port.
    - Why do open ports matter? If a port is "open", a service is listening. If that 
      service has a vulnerability or weak password, attackers can use it as a backdoor.
    """

    def __init__(self):
        # Common ports and their default services.
        # This helps analysts understand WHAT might be listening on an open port.
        self.common_ports = {
            21: "FTP (File Transfer Protocol) - Unencrypted, risky if exposed.",
            22: "SSH (Secure Shell) - Encrypted admin access.",
            23: "Telnet - Unencrypted admin access. VERY dangerous.",
            25: "SMTP (Email Routing)",
            53: "DNS (Domain Name System)",
            80: "HTTP (Web) - Unencrypted.",
            110: "POP3 (Email)",
            143: "IMAP (Email)",
            443: "HTTPS (Web) - Encrypted.",
            445: "SMB (Windows File Sharing) - Extremely risky if exposed to internet.",
            3306: "MySQL (Database) - Should not be exposed publicly.",
            3389: "RDP (Remote Desktop) - High target for ransomware if exposed."
        }

        # Ports that are considered highly dangerous if exposed to the public internet
        self.critical_ports = [23, 445, 3389]
        self.high_ports = [21, 22, 3306]

    def scan_target(self, target_ip, ports_to_scan=None):
        """
        Scans a target IP for open ports.
        
        Args:
            target_ip (str): The IP address or domain to scan.
            ports_to_scan (list): Optional list of ports. Defaults to self.common_ports.keys()
            
        Returns:
            Alert: An Alert object representing the scan results.
        """
        normalized_target = str(target_ip).strip().lower()
        if not settings.scanner_enabled:
            raise PermissionError("Port scanning is disabled by SOC_SCANNER_ENABLED")
        if not settings.scanner_lab_mode:
            raise PermissionError("Port scanning requires SOC_SCANNER_LAB_MODE=true")
        if normalized_target not in settings.scanner_allowed_targets:
            raise PermissionError(
                f"Target {target_ip!r} is outside the configured lab allowlist; "
                "set SOC_SCANNER_ALLOWED_TARGETS only to systems you are authorized to test."
            )
        target_ip = normalized_target
        if ports_to_scan is None:
            ports_to_scan = list(self.common_ports.keys())

        open_ports = []
        evidence = []
        overall_severity = "LOW"
        attack_type = "Reconnaissance / Normal Traffic"
        recommended_action = "No action required. Standard ports open."

        print(f"\n[i] Starting scan on {target_ip}...")
        
        for port in ports_to_scan:
            # EDUCATIONAL CONCEPT: Socket Creation
            # socket.AF_INET specifies we are using IPv4 addresses.
            # socket.SOCK_STREAM specifies we are using TCP (as opposed to UDP).
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Timeout is crucial! If a firewall drops the packet, the connection 
            # might hang forever. 1 second keeps the scan moving.
            s.settimeout(1.0)
            
            try:
                # connect_ex returns 0 if the connection succeeded (port is OPEN)
                # It returns an error indicator (like 111 for connection refused) if CLOSED
                result = s.connect_ex((target_ip, port))
                if result == 0:
                    service_desc = self.common_ports.get(port, "Unknown Service")
                    open_ports.append(port)
                    evidence.append(f"Port {port} is OPEN ({service_desc})")
                    
                    # Update Severity based on risky ports
                    if port in self.critical_ports:
                        overall_severity = "CRITICAL"
                        attack_type = "Critical Service Exposure"
                        recommended_action = "IMMEDIATELY block this port on the external firewall. Use a VPN for access."
                    elif port in self.high_ports and overall_severity != "CRITICAL":
                        overall_severity = "HIGH"
                        attack_type = "Risky Service Exposure"
                        recommended_action = "Restrict access to trusted IPs only. Ensure strong authentication."
                    elif overall_severity not in ["CRITICAL", "HIGH"]:
                        overall_severity = "MEDIUM"
                        attack_type = "Standard Service Exposure"
                        recommended_action = "Monitor logs for exploitation attempts on exposed services."
            except Exception as e:
                # If DNS resolution fails or network is unreachable
                pass
            finally:
                # Always close the socket to free up system resources
                s.close()

        # If no ports were found open
        if not open_ports:
            evidence.append("No open ports detected from the scanned list.")
            overall_severity = "LOW"
            attack_type = "None"
            recommended_action = "No action required. Target appears secure."

        risk_score = {"LOW": 10, "MEDIUM": 40, "HIGH": 75, "CRITICAL": 95}.get(overall_severity, 0)

        return Alert(
            module="port_scanner",
            source=target_ip,
            severity=overall_severity,
            attack_type=attack_type,
            risk_score=risk_score,
            evidence=evidence,
            recommended_action=recommended_action,
            open_ports=open_ports
        )


