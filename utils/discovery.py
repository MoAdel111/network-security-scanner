import re
import subprocess


def discover_network(network_range, logger=None):
    if logger:
        logger.info(f"Starting host discovery on {network_range}")

    command = ["nmap", "-sn", network_range]
    result = subprocess.run(command, capture_output=True, text=True)

    if result.returncode != 0:
        if logger:
            logger.error(f"Discovery failed: {result.stderr}")
        return []

    live_hosts = []

    for line in result.stdout.splitlines():
        if "Nmap scan report for" in line:
            match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            if match:
                live_hosts.append(match.group(1))

    unique_hosts = sorted(set(live_hosts))

    if logger:
        logger.info(f"Discovered {len(unique_hosts)} live host(s): {unique_hosts}")

    return unique_hosts