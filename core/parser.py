from collections import defaultdict
from core.risk_rules import evaluate_service
from core.recommender import detect_device_type, generate_recommendations


def parse_nmap(file_name, target, logger=None):
    if logger:
        logger.info(f"Parsing scan results for {target}")

    with open(file_name, "r", encoding="utf-8", errors="ignore") as file:
        lines = file.readlines()

    findings = []

    for line in lines:
        parts = line.split()

        if len(parts) >= 3 and parts[1] == "open":
            port_field = parts[0]
            service = parts[2].lower()

            port_number = None
            if "/" in port_field:
                try:
                    port_number = int(port_field.split("/")[0])
                except ValueError:
                    port_number = None

            risk, note = evaluate_service(service, port_number)

            findings.append({
                "target": target,
                "port": port_field,
                "port_number": port_number,
                "service": service,
                "status": "open",
                "risk": risk,
                "note": note,
            })

    return findings


def enrich_hosts(findings):
    grouped = defaultdict(list)
    for item in findings:
        grouped[item["target"]].append(item)

    host_profiles = []

    for host, host_findings in grouped.items():
        device_type = detect_device_type(host_findings)
        recommendations = generate_recommendations(host_findings, device_type)

        host_profiles.append({
            "target": host,
            "device_type": device_type,
            "open_ports": len(host_findings),
            "findings": host_findings,
            "recommendations": recommendations,
        })

    return sorted(host_profiles, key=lambda x: x["target"])


def calculate_summary(findings):
    total_open_ports = len(findings)

    high_risk = sum(1 for item in findings if item["risk"] == "high")
    medium_risk = sum(1 for item in findings if item["risk"] == "medium")
    low_risk = sum(1 for item in findings if item["risk"] == "low")
    unknown_risk = sum(1 for item in findings if item["risk"] == "unknown")

    risk_priority = {"high": 1, "medium": 2, "low": 3, "unknown": 4}

    findings.sort(
        key=lambda item: (
            risk_priority[item["risk"]],
            item["target"],
            item["port_number"] if item["port_number"] is not None else 999999,
        )
    )

    return total_open_ports, high_risk, medium_risk, low_risk, unknown_risk