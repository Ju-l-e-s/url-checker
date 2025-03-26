import logging
import logging.handlers


class CustomFormatter(logging.Formatter):
    """
    Custom formatter with color support for console output.

    Colors are applied based on the log level.

    :param fmt: The format string.
    :type fmt: str
    :param datefmt: The date format string.
    :type datefmt: str or None
    """
    # ANSI escape sequences for colors
    grey = "\x1b[38;21m"
    green = "\x1b[32;21m"
    yellow = "\x1b[33;21m"
    red = "\x1b[31;21m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"

    FORMATS = {
        logging.DEBUG: grey + "%(asctime)s - %(levelname)s - %(funcName)s - %(message)s" + reset,
        logging.INFO: green + "%(asctime)s - %(levelname)s - %(funcName)s - %(message)s" + reset,
        logging.WARNING: yellow + "%(asctime)s - %(levelname)s - %(funcName)s - %(message)s" + reset,
        logging.ERROR: red + "%(asctime)s - %(levelname)s - %(funcName)s - %(message)s" + reset,
        logging.CRITICAL: bold_red + "%(asctime)s - %(levelname)s - %(funcName)s - %(message)s" + reset
    }

    def format(self, record):
        # Choisir le format en fonction du niveau de log
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt, "%Y-%m-%d %H:%M:%S")
        # Si le décorateur a passé 'real_func', utilisez-le pour le champ funcName
        if hasattr(record, 'real_func'):
            record.funcName = record.real_func
        return formatter.format(record)


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
    logger.setLevel(logging.DEBUG)

    # File handler: format classique sans couleurs
    file_formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(funcName)s - %(message)s", "%Y-%m-%d %H:%M:%S"
    )
    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=5 * 1024 * 1024, backupCount=5, encoding='utf-8'
    )
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    # Console handler: avec formatage coloré
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(CustomFormatter())
    logger.addHandler(console_handler)

    logger.info("Logger configured successfully")
    _logger = logger
    return logger
