import os
from datetime import datetime

from config import (
    REPORTS_DIR,
    JSON_DIR,
    AUTO_CREATE_DIRS,
    DELETE_RAW_SCANS_AFTER_RUN,
    DISCOVERY_ENABLED,
    PDF_ENABLED,
    AUTHORIZED_USE_ONLY,
    EXCLUDE_HOSTS,
)
from utils.logger import setup_logger
from utils.network_utils import get_network_range
from utils.discovery import discover_network
from core.scanner import run_nmap_scan
from core.parser import parse_nmap, calculate_summary, enrich_hosts
from reports.report_writer import write_text_report, write_json_report
from reports.pdf_writer import write_pdf_report


def main():
    logger = setup_logger()

    if AUTHORIZED_USE_ONLY:
        logger.info("Authorized-use mode enabled. Scan only networks you own or are permitted to assess.")

    if AUTO_CREATE_DIRS:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        JSON_DIR.mkdir(parents=True, exist_ok=True)

    logger.info("Network Security Scanner started")

    now = datetime.now()
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
    stamp = now.strftime("%Y-%m-%d_%H-%M-%S")

    text_report = REPORTS_DIR / f"report_{stamp}.txt"
    pdf_report = REPORTS_DIR / f"report_{stamp}.pdf"
    json_report = JSON_DIR / f"report_{stamp}.json"

    network_range = get_network_range()
    if not network_range:
        logger.error("Could not detect network range.")
        return

    logger.info(f"Detected network range: {network_range}")

    if DISCOVERY_ENABLED:
        targets = discover_network(network_range, logger=logger)
    else:
        logger.error("Discovery is disabled in config.")
        return

    targets = [t for t in targets if t not in EXCLUDE_HOSTS]

    if not targets:
        logger.warning("No live targets found.")
        return

    logger.info(f"Targets to scan: {targets}")

    all_findings = []
    raw_scan_files = []

    for target in targets:
        scan_file = run_nmap_scan(target, logger=logger)
        if scan_file:
            raw_scan_files.append(scan_file)
            findings = parse_nmap(scan_file, target, logger=logger)
            all_findings.extend(findings)

    host_profiles = enrich_hosts(all_findings) if all_findings else []

    total_open_ports, high_risk, medium_risk, low_risk, unknown_risk = calculate_summary(all_findings) if all_findings else (0, 0, 0, 0, 0)

    summary = {
        "total_open_ports": total_open_ports,
        "high_risk": high_risk,
        "medium_risk": medium_risk,
        "low_risk": low_risk,
        "unknown_risk": unknown_risk,
    }

    write_text_report(
        text_report,
        all_findings,
        host_profiles,
        total_open_ports,
        high_risk,
        medium_risk,
        low_risk,
        unknown_risk,
        timestamp,
        targets
    )

    write_json_report(
        json_report,
        timestamp,
        targets,
        summary,
        host_profiles,
        all_findings
    )

    if PDF_ENABLED:
        write_pdf_report(
            pdf_report,
            all_findings,
            host_profiles,
            total_open_ports,
            high_risk,
            medium_risk,
            low_risk,
            unknown_risk,
            timestamp,
            targets
        )

    logger.info("Run completed successfully")
    logger.info(f"TXT report: {text_report}")
    logger.info(f"JSON report: {json_report}")
    logger.info(f"PDF report: {pdf_report}")

    if DELETE_RAW_SCANS_AFTER_RUN:
        for scan_file in raw_scan_files:
            try:
                os.remove(scan_file)
                logger.info(f"Deleted raw scan file: {scan_file}")
            except OSError as e:
                logger.warning(f"Could not delete scan file {scan_file}: {e}")


if __name__ == "__main__":
    main()