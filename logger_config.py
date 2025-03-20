import logging
import logging.handlers

class CustomFormatter(logging.Formatter):
    """
    Custom formatter that uses the real function name provided in the extra data.

    :param fmt: The format string.
    :type fmt: str
    :param datefmt: The date format string.
    :type datefmt: str or None
    :return: None
    :rtype: None
    """
    def format(self, record):
        if hasattr(record, 'real_func'):
            record.funcName = record.real_func
        return super().format(record)

_logger = None

def setup_logger(log_file: str = 'phishing_detector.log') -> logging.Logger:
    """
    Set up and return a configured logger for the phishing detector application.
    The configuration is applied only once.

    :param log_file: The filename for the log file
    :type log_file: str
    :return: A configured logger instance
    :rtype: logging.Logger
    """
    global _logger
    if _logger is not None:
        return _logger

    logger = logging.getLogger("phishing_detector")
    logger.setLevel(logging.DEBUG)  # Capture DEBUG messages for function tracing

    if not logger.handlers:
        formatter = CustomFormatter(
            "%(asctime)s - %(levelname)s - %(name)s - %(funcName)s - %(message)s"
        )
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=5 * 1024 * 1024, backupCount=5, encoding='utf-8'
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    logger.info("Logger configured successfully")
    _logger = logger
    return logger
