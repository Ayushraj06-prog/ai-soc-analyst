import re
from models.alert import Alert

class LogAnalyzer:
    """
    A beginner-friendly Log Analyzer that acts like a basic SOC (Security Operations Center) analyst.
    It reads logs, tracks failed logins per IP, and detects brute-force behavior.
    """

    def __init__(self):
        # We use a dictionary (hashmap) to track failed login attempts per IP address.
        # Format: {"192.168.1.5": 3, "10.0.0.1": 1}
        self.failed_logins = {}

    def parse_log_entry(self, log_entry):
        """
        Parses a single log entry to extract relevant information like the IP address and action.
        """
        # A simple regular expression to find an IPv4 address in the text
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ip_match = re.search(ip_pattern, log_entry)
        
        ip_address = ip_match.group(0) if ip_match else "Unknown IP"
        
        # Check if the log indicates a failed login
        is_failure = "failed login" in log_entry.lower()
        
        return {
            "ip": ip_address,
            "is_failure": is_failure,
            "original_log": log_entry
        }

    def analyze_logs(self, logs):
        """
        Takes a list of log entries, analyzes them, and generates alerts.
        """
        alerts = []

        # Step 1: Process each log entry
        for log in logs:
            parsed = self.parse_log_entry(log)
            ip = parsed["ip"]

            if parsed["is_failure"]:
                # If the IP is not in our dictionary yet, add it with a count of 1
                if ip not in self.failed_logins:
                    self.failed_logins[ip] = 1
                # If it's already there, increment the count
                else:
                    self.failed_logins[ip] += 1

        # Step 2: Generate Alerts based on our dictionary
        for ip, count in self.failed_logins.items():
            if count >= 10:
                severity = "CRITICAL"
                attack_type = "Severe Brute-Force Attack"
                evidence = f"{count} failed login attempts from a single IP in a short period."
                recommended_action = "Block IP immediately on firewall. Reset affected user passwords."
            elif count >= 5:
                severity = "HIGH"
                attack_type = "Brute-Force Attack"
                evidence = f"{count} failed login attempts detected."
                recommended_action = "Block IP on firewall. Monitor for successful logins."
            elif count >= 3:
                severity = "MEDIUM"
                attack_type = "Suspicious Login Activity"
                evidence = f"{count} failed login attempts. Potential password guessing."
                recommended_action = "Monitor IP. Require MFA for affected accounts."
            else:
                severity = "LOW"
                attack_type = "Normal Failure"
                evidence = f"Occasional failed logins ({count} attempt(s)). Might be a user typo."
                recommended_action = "No action required."

            risk_score = {"LOW": 20, "MEDIUM": 50, "HIGH": 80, "CRITICAL": 100}.get(severity, 0)
            
            alerts.append(Alert(
                module="log_analyzer",
                source=ip,
                severity=severity,
                attack_type=attack_type,
                risk_score=risk_score,
                evidence=[evidence],
                recommended_action=recommended_action
            ))

        return alerts

