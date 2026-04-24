import ipaddress
import socket


def get_local_ip():
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)

        if local_ip.startswith("127."):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
            finally:
                s.close()

        return local_ip
    except Exception:
        return None


def get_network_range():
    local_ip = get_local_ip()

    if not local_ip:
        return None

    network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
    return str(network)