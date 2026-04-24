def detect_device_type(findings_for_host):
    ports = {item["port_number"] for item in findings_for_host if item["port_number"] is not None}
    services = {item["service"] for item in findings_for_host}

    if {53, 23, 80}.intersection(ports) and "upnp" in services:
        return "Router / ONT / Network Device"

    if "rtsp" in services or {5000, 7000}.intersection(ports):
        return "Camera / DVR / Media Device"

    if {135, 139, 445}.intersection(ports):
        return "Windows Device"

    if 22 in ports and len(ports) <= 3:
        return "Linux / Network Appliance"

    return "General Network Host"


def generate_recommendations(findings_for_host, device_type):
    recommendations = []
    ports = {item["port_number"] for item in findings_for_host if item["port_number"] is not None}
    services = {item["service"] for item in findings_for_host}

    if 23 in ports or "telnet" in services:
        recommendations.append("Disable Telnet and use SSH if remote administration is required.")

    if 445 in ports or "microsoft-ds" in services or "microsoft-ds?" in services:
        recommendations.append("Restrict SMB access, disable unused file sharing, and verify firewall rules.")

    if 139 in ports or "netbios-ssn" in services:
        recommendations.append("Disable NetBIOS over TCP/IP if not required.")

    if "upnp" in services:
        recommendations.append("Disable UPnP unless automatic port mapping is specifically needed.")

    if "rtsp" in services:
        recommendations.append("Protect camera/streaming services with strong credentials and restricted network access.")

    if 3389 in ports:
        recommendations.append("Restrict RDP to trusted sources and require strong authentication.")

    if device_type == "Router / ONT / Network Device":
        recommendations.append("Review admin access settings and disable unnecessary remote management features.")

    if not recommendations:
        recommendations.append("No urgent remediation identified. Continue monitoring and validate expected exposure.")

    return recommendations