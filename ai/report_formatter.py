"""
Report formatting module for presenting AI output.
"""
import datetime
import os
import json

def format_report(llm_response: str) -> str:
    """Wraps the LLM response in a professional SOC report template."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    report =  "========================================\n"
    report += "    AI INCIDENT INVESTIGATION REPORT    \n"
    report += "========================================\n\n"
    
    report += llm_response.strip() + "\n\n"
    
    report += "========================================\n"
    report += f"Generated Timestamp: {timestamp}\n"
    report += "========================================\n"
    return report

def export_txt(formatted_report: str) -> str:
    """Exports the formatted text report to a file."""
    os.makedirs("exports/ai_reports", exist_ok=True)
    timestamp_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"exports/ai_reports/ai_report_{timestamp_str}.txt"
    
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(formatted_report)
    return filename

def export_json(llm_response: str, alerts: list, correlations: list, classifications: list) -> str:
    """Exports the report along with its structured data to a JSON file."""
    os.makedirs("exports/ai_reports", exist_ok=True)
    timestamp_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"exports/ai_reports/ai_report_{timestamp_str}.json"
    
    data = {
        "timestamp": datetime.datetime.now().isoformat(),
        "ai_analysis_raw": llm_response,
        "correlations": correlations,
        "classifications": classifications,
        "alerts": [a.to_dict() for a in alerts]
    }
    
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4)
    return filename
