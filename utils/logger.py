import logging
from datetime import datetime
from config import LOGS_DIR, AUTO_CREATE_DIRS


def setup_logger():
    if AUTO_CREATE_DIRS:
        LOGS_DIR.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("network_security_scanner")
    logger.setLevel(logging.INFO)

    if logger.handlers:
        return logger

    log_file = LOGS_DIR / f"run_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.log"

    formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setFormatter(formatter)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)

    return logger