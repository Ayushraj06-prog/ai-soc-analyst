"""
Prompt building module to instruct the LLM.
"""
import json

def build_investigation_prompt(alerts: list, correlations: list, classifications: list) -> str:
    """
    Builds the prompt instructing the LLM to generate an investigation report.
    """
    
    prompt = "You are an expert AI Security Operations Center (SOC) Analyst.\n"
    prompt += "Review the following security alerts, correlations, and classifications, and generate a professional incident investigation report.\n\n"
    
    prompt += "### PROVIDED DATA ###\n"
    
    prompt += "\n--- Correlated Events ---\n"
    if correlations:
        prompt += json.dumps(correlations, indent=2) + "\n"
    else:
        prompt += "No correlated events detected.\n"
        
    prompt += "\n--- Incident Classifications ---\n"
    if classifications:
        prompt += json.dumps(classifications, indent=2) + "\n"
    else:
        prompt += "No distinct incident classifications available.\n"
        
    prompt += "\n--- Individual Alerts ---\n"
    alerts_data = []
    for a in alerts:
        # Assuming alert object has a to_dict method
        if hasattr(a, 'to_dict'):
            alerts_data.append(a.to_dict())
        else:
            alerts_data.append(str(a))
            
    prompt += json.dumps(alerts_data, indent=2) + "\n"
    
    prompt += "\n### INSTRUCTIONS ###\n"
    prompt += "Based on the provided data, generate a report containing exactly the following sections in order:\n\n"
    prompt += "Executive Summary\n"
    prompt += "- A high-level overview of the incident.\n\n"
    prompt += "Threat Analysis\n"
    prompt += "- Detailed breakdown of the attack vector.\n\n"
    prompt += "Severity Justification\n"
    prompt += "- Why the overall severity was chosen.\n\n"
    prompt += "Confidence Assessment\n"
    prompt += "- Consider confidence score and risk score when determining whether the alert is likely a true positive, false positive, or requires further investigation.\n\n"
    prompt += "MITRE ATT&CK Mapping\n"
    prompt += "- List the mapped techniques and their descriptions.\n\n"
    prompt += "Incident Classification\n"
    prompt += "- Broad classification of the incident type.\n\n"
    prompt += "Business Impact\n"
    prompt += "- Potential consequences if unmitigated.\n\n"
    prompt += "False Positive Assessment\n"
    prompt += "- Likelihood of this being benign activity.\n\n"
    prompt += "Remediation Recommendations\n"
    prompt += "- Actionable steps to mitigate.\n\n"
    
    prompt += "Format your output strictly with the exact section headers above. Do not include conversational filler. Start directly with the 'Executive Summary' header.\n"
    
    return prompt
