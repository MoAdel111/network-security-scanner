import json
from config import JSON_REPORT_ENABLED, JSON_DIR, TEXT_REPORT_ENABLED


def write_text_report(
    report_name,
    findings,
    host_profiles,
    total_open_ports,
    high_risk,
    medium_risk,
    low_risk,
    unknown_risk,
    timestamp,
    targets
):
    if not TEXT_REPORT_ENABLED:
        return

    with open(report_name, "w", encoding="utf-8") as report:
        report.write("NETWORK SECURITY SCAN REPORT\n")
        report.write("=" * 70 + "\n\n")

        report.write("Targets Scanned:\n")
        for target in targets:
            report.write(f"- {target}\n")

        report.write(f"\nDate: {timestamp}\n\n")

        report.write("SUMMARY\n")
        report.write("-" * 70 + "\n")
        report.write(f"Total Open Ports: {total_open_ports}\n")
        report.write(f"High Risk: {high_risk}\n")
        report.write(f"Medium Risk: {medium_risk}\n")
        report.write(f"Low Risk: {low_risk}\n")
        report.write(f"Unknown Risk: {unknown_risk}\n\n")

        report.write("HOST PROFILES\n")
        report.write("-" * 70 + "\n")
        for host in host_profiles:
            report.write(f"Target: {host['target']}\n")
            report.write(f"Device Type: {host['device_type']}\n")
            report.write(f"Open Ports: {host['open_ports']}\n")
            report.write("Recommendations:\n")
            for rec in host["recommendations"]:
                report.write(f"  - {rec}\n")
            report.write("-" * 70 + "\n")

        report.write("\nDETAILED FINDINGS\n")
        report.write("-" * 70 + "\n")
        for item in findings:
            report.write(f"Target: {item['target']}\n")
            report.write(f"Port: {item['port']}\n")
            report.write(f"Service: {item['service']}\n")
            report.write(f"Status: {item['status']}\n")
            report.write(f"Risk: {item['risk']}\n")
            report.write(f"Note: {item['note']}\n")
            report.write("-" * 70 + "\n")


def write_json_report(json_name, timestamp, targets, summary, host_profiles, findings):
    if not JSON_REPORT_ENABLED:
        return

    JSON_DIR.mkdir(parents=True, exist_ok=True)

    payload = {
        "timestamp": timestamp,
        "targets": targets,
        "summary": summary,
        "host_profiles": host_profiles,
        "findings": findings,
    }

    with open(json_name, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=4)