import json
import datetime
from tools.url_checker import URLThreatChecker
from tools.log_analyzer import LogAnalyzer
from tools.port_scanner import PortScanner

class SecurityOrchestrator:
    """
    The central intelligence orchestrator.
    It runs all individual modules, collects their standardized alerts,
    and correlates them to find complex attack patterns.
    """
    def __init__(self):
        self.url_checker = URLThreatChecker()
        self.log_analyzer = LogAnalyzer()
        self.port_scanner = PortScanner()
        self.alerts = []

    def run_all(self, url_target, log_entries, ip_target):
        """Runs all modules and collects unified alerts."""
        self.alerts = [] # Reset alerts
        
        # 1. URL Analysis
        if url_target:
            self.alerts.append(self.url_checker.analyze_url(url_target))
            
        # 2. Log Analysis
        if log_entries:
            log_alerts = self.log_analyzer.analyze_logs(log_entries)
            self.alerts.extend(log_alerts)
            
        # 3. Port Scan
        if ip_target:
            self.alerts.append(self.port_scanner.scan_target(ip_target))
            
        return self.alerts

    def correlate_alerts(self):
        """
        EDUCATIONAL CONCEPT: Event Correlation.
        In a real SIEM, rules are written to detect when multiple low-level events
        combine into a high-level threat.
        We assign confidence scores based on how many overlapping data points exist.
        """
        correlated_findings = []
        
        # Check for specific conditions in our collected alerts
        has_failed_logins = any(a.module == 'log_analyzer' and a.severity in ['HIGH', 'CRITICAL'] for a in self.alerts)
        has_open_ssh = False
        has_phishing = False
        
        for alert in self.alerts:
            if alert.module == 'port_scanner' and any('Port 22 is OPEN' in str(ev) for ev in alert.evidence):
                has_open_ssh = True
            if alert.module == 'url_checker' and alert.severity in ['HIGH', 'CRITICAL']:
                has_phishing = True
                
        # Correlation Rule 1: SSH Brute Force
        if has_failed_logins and has_open_ssh:
            correlated_findings.append({
                "meta_alert": "Active SSH Brute Force Campaign",
                "severity": "CRITICAL",
                "confidence": "HIGH CONFIDENCE",
                "description": "Target has an exposed SSH port (22) AND is actively receiving numerous failed login attempts."
            })
            
        # Correlation Rule 2: Phishing + Credential Stuffing
        if has_failed_logins and has_phishing:
            correlated_findings.append({
                "meta_alert": "Phishing & Credential Stuffing Attack",
                "severity": "CRITICAL",
                "confidence": "MEDIUM CONFIDENCE",
                "description": "A high-risk phishing URL was detected concurrently with multiple failed logins, suggesting stolen credentials are being tested."
            })
            
        return correlated_findings

    def generate_soc_report(self):
        """Generates the final unified SOC report with dashboard formatting."""
        correlations = self.correlate_alerts()
        
        print("\n" + "="*80)
        print(" UNIFIED SOC SECURITY REPORT ".center(80))
        print("="*80)
        
        # --- EXECUTIVE SUMMARY ---
        print("\n [0] EXECUTIVE SUMMARY")
        print("-" * 80)
        critical_count = sum(1 for a in self.alerts if a.severity == 'CRITICAL')
        high_count = sum(1 for a in self.alerts if a.severity == 'HIGH')
        print(f" Total Alerts Generated:  {len(self.alerts)}")
        print(f" Critical Alerts:         {critical_count}")
        print(f" High Alerts:             {high_count}")
        print(f" Correlated Meta-Threats: {len(correlations)}")
        
        # --- INDIVIDUAL ALERTS ---
        print("\n [1] INDIVIDUAL MODULE FINDINGS")
        print("-" * 80)
        for alert in self.alerts:
            print(f" [+] ID: {alert.alert_id} | Source: {alert.source} | Module: {alert.module.upper()}")
            print(f"     Timestamp:   {alert.timestamp}")
            print(f"     Severity:    [{alert.severity}] | Score: {alert.risk_score}")
            print(f"     Attack Type: {alert.attack_type}")
            for ev in alert.evidence:
                print(f"     - {ev}")
            print()
            
        # --- CORRELATIONS ---
        print("\n [2] CORRELATED THREAT INTELLIGENCE (SIEM ENGINE)")
        print("-" * 80)
        if not correlations:
            print(" [+] No correlated meta-threats detected.")
        else:
            for c in correlations:
                print(f" [!] META-ALERT: [{c['severity']}] {c['meta_alert']} ({c['confidence']})")
                print(f"     Analysis: {c['description']}\n")
                
        # --- MITIGATION ---
        print("\n [3] SOC ANALYST NOTES & RECOMMENDATIONS")
        print("-" * 80)
        highest_severity = "LOW"
        for alert in self.alerts:
            if alert.severity == 'CRITICAL': highest_severity = 'CRITICAL'
            elif alert.severity == 'HIGH' and highest_severity not in ['CRITICAL']: highest_severity = 'HIGH'
            elif alert.severity == 'MEDIUM' and highest_severity not in ['CRITICAL', 'HIGH']: highest_severity = 'MEDIUM'
            
        print(f" Overall Network Risk: [{highest_severity}]")
        print(" Actions Required:")
        for alert in self.alerts:
            if alert.severity in ['HIGH', 'CRITICAL']:
                print(f"  -> {alert.alert_id} ({alert.source}): {alert.recommended_action}")
        for c in correlations:
            print(f"  -> URGENT: Investigate {c['meta_alert']} immediately.")
            
        print("="*80 + "\n")
        
        # Auto-export the report
        self.export_report_json(correlations)
        self.export_report_txt(correlations)

    def export_report_json(self, correlations):
        """Exports the report to a JSON file."""
        import os
        os.makedirs("exports", exist_ok=True)
        
        timestamp_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"exports/report_{timestamp_str}.json"
        
        report_data = {
            "meta_threats": correlations,
            "alerts": [a.to_dict() for a in self.alerts]
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(report_data, f, indent=4)
            print(f" [+] Successfully exported JSON report to {filename}")
        except Exception as e:
            print(f" [-] Failed to export JSON: {e}")

    def export_report_txt(self, correlations):
        """Exports the report to a TXT file."""
        import os
        os.makedirs("exports", exist_ok=True)
        
        timestamp_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"exports/report_{timestamp_str}.txt"
        
        try:
            with open(filename, 'w') as f:
                f.write("=== UNIFIED SOC SECURITY REPORT ===\n\n")
                f.write(f"Generated at: {datetime.datetime.now()}\n\n")
                
                f.write("--- CORRELATED THREATS ---\n")
                for c in correlations:
                    f.write(f"[{c['severity']}] {c['meta_alert']} ({c['confidence']})\n")
                    f.write(f"Analysis: {c['description']}\n\n")
                
                f.write("--- INDIVIDUAL ALERTS ---\n")
                for a in self.alerts:
                    f.write(f"ID: {a.alert_id} | Module: {a.module} | Source: {a.source}\n")
                    f.write(f"Severity: {a.severity} | Attack Type: {a.attack_type}\n")
                    f.write("Evidence:\n")
                    for ev in a.evidence:
                        f.write(f" - {ev}\n")
                    f.write("\n")
                    
            print(f" [+] Successfully exported TXT report to {filename}")
        except Exception as e:
            print(f" [-] Failed to export TXT: {e}")

    def run_ai_investigation(self, incident_id=None, *, force=False, dry_run=False, show_prompt=False):
        """Run the hardened persisted Phase 6 workflow; in-memory alerts are not sent to a model."""
        if not incident_id:
            print("Phase 6 requires a persisted Phase 5 incident. Use: python -m investigation <incident_id>")
            return None
        from investigation.service import InvestigationService
        from app.config import settings
        service=InvestigationService(settings.database_path)
        return service.investigate(incident_id,force=force,dry_run=dry_run,show_prompt=show_prompt,created_by="cli")

