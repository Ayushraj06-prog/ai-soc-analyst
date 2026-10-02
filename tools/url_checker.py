import urllib.parse

from models.alert import Alert

class URLThreatChecker:
    """
    A beginner-friendly URL threat checker that uses basic heuristics 
    to detect potentially malicious URLs.
    """

    def __init__(self):
        # A list of keywords commonly used in phishing URLs
        self.suspicious_keywords = [
            'login', 'verify', 'secure', 'account', 'update', 
            'banking', 'paypal', 'auth', 'signin'
        ]
        # High-risk top-level domains commonly abused by attackers
        self.suspicious_tlds = ['.xyz', '.tk', '.top', '.click', '.ru']

    def analyze_url(self, url):
        """
        Analyzes a single URL based on basic cybersecurity heuristics.
        
        Args:
            url (str): The URL to check.
            
        Returns:
            Alert: An Alert object representing the threat analysis.
        """
        threat_score = 0
        evidence = []
        attack_type = "None"
        recommended_action = "No action required. URL appears safe."

        if not url.startswith('http://') and not url.startswith('https://'):
            parsed_url = urllib.parse.urlparse('http://' + url)
        else:
            parsed_url = urllib.parse.urlparse(url)

        # 1. Detect Suspicious Keywords
        url_lower = url.lower()
        for keyword in self.suspicious_keywords:
            if keyword in url_lower:
                threat_score += 25
                evidence.append(f"Suspicious keyword found: '{keyword}'")
                attack_type = "Phishing / Social Engineering"

        # 2. Detect '@' Symbol
        if '@' in parsed_url.netloc:
            threat_score += 40
            evidence.append("Contains '@' symbol (often used to obscure the true destination)")
            attack_type = "Phishing / Credential Harvesting"

        # 3. Detect Excessive Hyphens in Domain
        domain = parsed_url.netloc
        if domain.count('-') > 3:
            threat_score += 20
            evidence.append(f"Excessive hyphens in domain (Found {domain.count('-')})")

        # 4. Detect Very Long URLs
        if len(url) > 75:
            threat_score += 15
            evidence.append(f"URL is unusually long ({len(url)} characters)")

        # 5. IP Address instead of Domain Name
        domain_parts = domain.replace(':', '').split('.')
        if all(part.isdigit() for part in domain_parts) and len(domain_parts) == 4:
            threat_score += 35
            evidence.append("URL uses a direct IP address instead of a domain name")
            attack_type = "Suspicious Hosting / Malware Delivery"

        # 6. Suspicious TLD Detection
        for tld in self.suspicious_tlds:
            if domain.endswith(tld):
                threat_score += 30
                evidence.append(f"Uses a high-risk Top-Level Domain ({tld})")
                if attack_type == "None":
                    attack_type = "Suspicious Domain"

        threat_score = min(threat_score, 100)

        # Determine Threat Level
        if threat_score == 0:
            threat_level = "LOW"
        elif threat_score < 40:
            threat_level = "MEDIUM"
        elif threat_score < 70:
            threat_level = "HIGH"
        else:
            threat_level = "CRITICAL"

        # Determine Recommended Action based on severity
        if threat_level == "MEDIUM":
            recommended_action = "Proceed with caution. Verify the sender."
        elif threat_level == "HIGH":
            recommended_action = "Do not click. Block the domain in web proxy/firewall."
        elif threat_level == "CRITICAL":
            recommended_action = "Block immediately. Investigate potential internal clicks via proxy logs."

        return Alert(
            module="url_checker",
            source=url,
            severity=threat_level,
            attack_type=attack_type,
            risk_score=threat_score,
            evidence=evidence,
            recommended_action=recommended_action
        )


