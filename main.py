from tools.url_checker import URLThreatChecker
from tools.log_analyzer import LogAnalyzer
from tools.port_scanner import PortScanner
from orchestrator import SecurityOrchestrator
from models.alert import Alert

def display_unified_alert(alert):
    """Prints a single unified alert to the console."""
    print("\n" + "="*70)
    print(f" Module Report: [{alert.module.upper()}] - {alert.source}")
    print("="*70)
    print(f" [*] Alert ID:           {alert.alert_id}")
    print(f" [*] Timestamp:          {alert.timestamp}")
    print(f" [*] Risk Score:         {alert.risk_score}")
    print(f" [*] Risk Level:         [{alert.severity}]")
    print(f" [*] Attack Type:        {alert.attack_type}")
    
    if alert.evidence:
        print("\n [!] Evidence Detected:")
        for reason in alert.evidence:
            print(f"     - {reason}")
    else:
        print("\n [+] No active threats detected.")
        
    print(f"\n [>] Recommended Action: {alert.recommended_action}")
    print("="*70 + "\n")

def run_url_tests():
    checker = URLThreatChecker()
    test_urls = ["http://www.secure-login-update.com", "http://free-iphone.xyz"]
    print("\nRunning Automated URL Tests...")
    for url in test_urls:
        report = checker.analyze_url(url)
        display_unified_alert(report)

def run_log_tests():
    analyzer = LogAnalyzer()
    test_logs = [
        "10:00 AM - Failed login from 10.0.0.1",
        "10:13 AM - Failed login from 10.10.10.10",
        "10:14 AM - Failed login from 10.10.10.10",
        "10:15 AM - Failed login from 10.10.10.10",
        "10:16 AM - Failed login from 10.10.10.10",
        "10:17 AM - Failed login from 10.10.10.10"
    ]
    print("\nRunning Automated Log Tests...")
    alerts = analyzer.analyze_logs(test_logs)
    for alert in alerts:
        display_unified_alert(alert)

def run_port_tests():
    scanner = PortScanner()
    test_target = "127.0.0.1"
    print(f"\nRunning Automated Port Scan Test on {test_target}...")
    report = scanner.scan_target(test_target)
    display_unified_alert(report)

def run_orchestrator_demo():
    """Runs the Orchestrator with an explicit correlation scenario."""
    print("\n[i] Starting Orchestrator Unified Scan...")
    orchestrator = SecurityOrchestrator()
    
    # 1. Provide a malicious URL
    url_target = "http://www.secure-login-update.com"
    
    # 2. Provide log entries indicating a brute force attack from 192.168.1.100
    log_entries = [
        "10:00 AM - Failed login from 192.168.1.100",
        "10:01 AM - Failed login from 192.168.1.100",
        "10:02 AM - Failed login from 192.168.1.100",
        "10:03 AM - Failed login from 192.168.1.100",
        "10:04 AM - Failed login from 192.168.1.100",
    ]
    
    # 3. Port scan on localhost
    ip_target = "127.0.0.1"
    
    orchestrator.run_all(url_target, log_entries, ip_target)
    
    # In a real environment, port 22 might not be open on localhost.
    # To guarantee the SIEM correlation rule triggers for educational purposes,
    # we inject a fake port scan alert showing Port 22 open on the attacking IP.
    orchestrator.alerts.append(Alert(
        module="port_scanner",
        source="192.168.1.100",
        risk_score=75,
        severity="HIGH",
        attack_type="Risky Service Exposure",
        evidence=["Port 22 is OPEN (SSH)"],
        recommended_action="Restrict access to trusted IPs only."
    ))
    
    orchestrator.generate_soc_report()

def run_ai_investigation_demo():
    """Launch Phase 6 only for an already persisted Phase 5 incident."""
    incident_id=input("Persisted incident ID to investigate > ").strip()
    if not incident_id:
        print("No incident ID supplied.")
        return
    from investigation.__main__ import main as investigation_main
    investigation_main([incident_id])

def main():
    while True:
        print("\n=========================================")
        print("  AI Cybersecurity Assistant (Phase 5)   ")
        print("=========================================")
        print(" 1. URL Threat Checker")
        print(" 2. Log Analyzer")
        print(" 3. Port Scanner")
        print(" 4. Run Unified Orchestrator Demo")
        print(" 5. Exit")
        print(" 6. Run AI Investigation")
        
        try:
            choice = input("\nSelect an option (1-6) > ").strip()
            
            if choice == '1':
                checker = URLThreatChecker()
                user_url = input("Enter a URL to check > ").strip()
                if user_url:
                    report = checker.analyze_url(user_url)
                    display_unified_alert(report)
            elif choice == '2':
                run_log_tests()
            elif choice == '3':
                run_port_tests()
            elif choice == '4':
                run_orchestrator_demo()
            elif choice == '5' or choice.lower() in ['quit', 'exit']:
                print("Exiting...")
                break
            elif choice == '6':
                run_ai_investigation_demo()
            else:
                print("Invalid choice. Please try again.")
                
        except KeyboardInterrupt:
            print("\nExiting...")
            break

if __name__ == "__main__":
    main()
