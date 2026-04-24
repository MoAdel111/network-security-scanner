def evaluate_service(service, port=None):
    service = (service or "").lower().strip()

    service_rules = {
        "telnet": ("high", "Unencrypted remote access service. High risk."),
        "ftp": ("high", "FTP may allow insecure file transfer. High risk."),
        "smb": ("high", "SMB can expose file sharing and may be targeted. High risk."),
        "microsoft-ds": ("high", "SMB service detected. Common attack surface. High risk."),
        "microsoft-ds?": ("high", "Possible SMB service detected. Common attack surface. High risk."),
        "rdp": ("high", "Remote desktop service detected. High-value target."),
        "ms-wbt-server": ("high", "Remote desktop service detected. High-value target."),

        "ssh": ("medium", "Remote access service detected. Review configuration."),
        "msrpc": ("medium", "Microsoft RPC detected. Requires review."),
        "netbios-ssn": ("medium", "NetBIOS service detected. Review exposure."),
        "upnp": ("medium", "UPnP detected. May expose internal services."),
        "rtsp": ("medium", "Streaming service detected (camera/media)."),
        "smtp": ("medium", "Mail service detected. Review relay and exposure."),
        "imap": ("medium", "Mail retrieval service detected. Review encryption and access."),
        "pop3": ("medium", "Mail retrieval service detected. Review encryption and access."),

        "http": ("low", "Web service detected. Check configuration."),
        "https": ("low", "Secure web service detected."),
        "domain": ("low", "DNS service detected."),

        "tcpwrapped": ("unknown", "Service is filtered or hidden."),
        "unknown": ("unknown", "Manual review needed."),
    }

    port_rules = {
        21: ("high", "FTP detected."),
        22: ("medium", "SSH detected."),
        23: ("high", "Telnet detected."),
        25: ("medium", "SMTP detected."),
        53: ("low", "DNS detected."),
        80: ("low", "HTTP detected."),
        110: ("medium", "POP3 detected."),
        135: ("medium", "MSRPC detected."),
        139: ("medium", "NetBIOS detected."),
        143: ("medium", "IMAP detected."),
        443: ("low", "HTTPS detected."),
        445: ("high", "SMB detected."),
        3389: ("high", "RDP detected."),
        5000: ("medium", "Possible RTSP or device service detected."),
        7000: ("medium", "Possible RTSP or streaming service detected."),
        8080: ("low", "HTTP alternative detected."),
        8443: ("low", "HTTPS alternative detected."),
        49152: ("low", "Dynamic/private port. Usually temporary."),
        49153: ("low", "Dynamic/private port. Usually temporary."),
    }

    if service in service_rules and service != "tcpwrapped":
        return service_rules[service]

    if port is not None and port in port_rules:
        return port_rules[port]

    if service in service_rules:
        return service_rules[service]

    if port is not None:
        if 0 <= port <= 1023:
            return "medium", "Well-known port but unidentified service. Needs review."
        if 1024 <= port <= 49151:
            return "medium", "Registered port. Possibly application service."
        if 49152 <= port <= 65535:
            return "low", "Dynamic/private port. Usually temporary."

    return "unknown", "Manual review needed."