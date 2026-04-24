import subprocess
from datetime import datetime
from pathlib import Path

from config import SCANS_DIR, AUTO_CREATE_DIRS, SCAN_TOP_PORTS, NMAP_TIMING, NMAP_SERVICE_DETECTION


def safe_target_name(target):
    return target.replace(":", "_").replace("/", "_").replace("\\", "_").replace(".", "_")


def run_nmap_scan(target, logger=None):
    if AUTO_CREATE_DIRS:
        Path(SCANS_DIR).mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_file = SCANS_DIR / f"scan_{safe_target_name(target)}_{timestamp}.txt"

    command = ["nmap", f"-{NMAP_TIMING}", "--top-ports", str(SCAN_TOP_PORTS)]

    if NMAP_SERVICE_DETECTION:
        command.append("-sV")

    command.extend([target, "-oN", str(output_file)])

    if logger:
        logger.info(f"Scanning target {target}")
        logger.info(f"Command: {' '.join(command)}")

    result = subprocess.run(command, capture_output=True, text=True)

    if result.returncode != 0:
        if logger:
            logger.error(f"Scan failed for {target}: {result.stderr}")
        return None

    if logger:
        logger.info(f"Scan completed for {target}. Output: {output_file}")

    return str(output_file)