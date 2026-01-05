import logging
import sys

def _setup_logging(level: int = logging.INFO) -> None:
    logging.basicConfig(
        level=level,
        # format="%(asctime)s %(levelname)s %(name)s - %(message)s",
        stream=sys.stdout,
    )

def get_logger(name: str) -> logging.Logger:
    _setup_logging(level=logging.INFO)
    return logging.getLogger(name)
