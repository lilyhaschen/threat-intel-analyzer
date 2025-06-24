# Advanced Cybersecurity Project: Threat Intelligence Analyzer
# Created by Lily 🐰💻

import json
import requests
import sys
import argparse
from datetime import datetime
from pathlib import Path

THREAT_FEED_URL = "https://api.threatfeeds.example.com/iocs"  # Replace with real endpoint
BLACKLISTED_IPS = {"192.168.1.100", "10.0.0.42"}  # Use a set for faster lookup
REPORT_FILE = Path("threat_report_log.json")


def fetch_threat_data():
    try:
        response = requests.get(THREAT_FEED_URL, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"[ERROR] Network error fetching threat data: {e}", file=sys.stderr)
    except ValueError:
        print("[ERROR] Failed to decode threat data as JSON.", file=sys.stderr)
    return []


def analyze_iocs(iocs):
    timestamp = datetime.utcnow().isoformat()
    seen = set()
    report = []
    for ioc in iocs:
        ip = ioc.get("ip")
        if ip in BLACKLISTED_IPS and ip not in seen:
            seen.add(ip)
            report.append({
                "threat": ioc.get("threat_type", "unknown"),
                "ip": ip,
                "description": ioc.get("description", "N/A"),
                "severity": ioc.get("severity", "medium"),
                "geo": ioc.get("geo", "unknown"),
                "port": ioc.get("port", "N/A"),
                "timestamp": timestamp
            })
    return report


def save_report(report):
    if not report:
        return
    existing = []
    if REPORT_FILE.exists():
        with open(REPORT_FILE, 'r') as f:
            existing = json.load(f)
    existing.extend(report)
    with open(REPORT_FILE, 'w') as f:
        json.dump(existing, f, indent=2)
    print(f"[INFO] Report saved to {REPORT_FILE}")


def show_history():
    if REPORT_FILE.exists():
        with open(REPORT_FILE, 'r') as f:
            history = json.load(f)
        print(json.dumps(history, indent=2))
    else:
        print("[INFO] No report history found.")


def main():
    parser = argparse.ArgumentParser(description="Threat Intelligence Analyzer")
    parser.add_argument("--history", action="store_true", help="Show saved threat history")
    args = parser.parse_args()

    if args.history:
        show_history()
        return

    print("[INFO] Fetching threat intel feed...")
    iocs = fetch_threat_data()
    if not iocs:
        print("[INFO] No threat data available.")
        return

    print("[INFO] Analyzing indicators of compromise...")
    report = analyze_iocs(iocs)
    if report:
        print("[ALERT] Threats Detected:")
        print(json.dumps(report, indent=2))
        save_report(report)
    else:
        print("[INFO] No blacklisted IPs found.")


if __name__ == "__main__":
    main()
