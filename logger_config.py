import logging
import sys
from pathlib import Path


def setup_logger(verbose=True):
    """
    Configure logging for the phishing detector.

    :param verbose: Whether to enable verbose output (DEBUG level)
    :type verbose: bool
    :return: None
    """
    # Create the logs directory if it doesn't exist
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)

    # Configure the log level based on the verbose flag
    root_level = logging.DEBUG if verbose else logging.INFO
    file_level = logging.DEBUG  # Always log details to the file

    # Configure the root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(root_level)

    # Remove existing handlers to avoid duplicates
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Create a detailed log format
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Configure the file handler
    file_handler = logging.FileHandler("logs/phishing_detector.log")
    file_handler.setLevel(file_level)
    file_handler.setFormatter(formatter)

    # Configure the console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(root_level)
    console_handler.setFormatter(formatter)

    # Add the handlers to the logger
    # Ajouter les handlers au logger
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)

    # Logger initialization
    root_logger.info("Logging initialized")
    if verbose:
        root_logger.debug("Verbose mode enabled")