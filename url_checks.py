import re
import requests
import tldextract
import logging
import functools
from urllib.parse import urlparse, parse_qs
from config import Config
from logger_config import setup_logger


def log_call(func):
    """
    Decorator to log when a function is entered and exited, including its arguments and return value.

    :param func: The function to decorate.
    :type func: function
    :return: The wrapped function.
    :rtype: function
    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        self = args[0]  # Assumes 'self' is the first argument (i.e. a class instance)
        self.logger.debug(
            "Entering %s with args: %s, kwargs: %s",
            func.__name__, args[1:], kwargs, extra={'real_func': func.__name__}, stacklevel=3
        )
        result = func(*args, **kwargs)
        self.logger.debug(
            "Exiting %s with result: %s",
            func.__name__, result, extra={'real_func': func.__name__}, stacklevel=3
        )
        return result

    return wrapper


class URLAnalyzer:
    """
    A class to perform phishing detection and URL analysis.

    :param: None
    :return: None
    :rtype: None
    """

    def __init__(self):
        """
        Initializes the URLAnalyzer instance, loads configuration constants,
        and sets up a dedicated logger instance.

        :param: None
        :return: None
        :rtype: None
        """
        self.logger = logging.getLogger(f"phishing_detector.{self.__class__.__name__}")
        config = Config()
        self.api_key = config.API_KEY
        self.safe_browsing_url = config.SAFE_BROWSING_URL
        self.trusted_domains = config.TRUSTED_DOMAINS
        self.suspicious_keys = config.SUSPICIOUS_KEYS
        self.shorteners = config.SHORTENERS
        self.suspicious_words = config.SUSPICIOUS_WORDS

    @log_call
    def check_domain(self, url: str) -> str:
        """
        Checks if the URL's domain is in the trusted domains list.

        :param url: The URL to check.
        :type url: str
        :return: A message indicating whether the domain is trusted.
        :rtype: str
        """
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}"
        if domain in self.trusted_domains:
            return f"✅ The domain {domain} is trusted."
        return f"⚠️ WARNING: The domain {domain} is not in the trusted list!"

    @log_call
    def check_subdomain(self, url: str) -> str:
        """
        Checks if the given URL has a suspicious subdomain that mimics a trusted domain.

        :param url: The URL to check.
        :type url: str
        :return: A warning if the subdomain is suspicious, otherwise a confirmation message.
        :rtype: str
        """
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}"
        subdomain = extracted.subdomain
        if domain in self.trusted_domains and subdomain:
            return (f"⚠️ WARNING: The URL uses a suspicious subdomain ({subdomain}). "
                    f"It may be trying to impersonate {domain}!")
        return "✅ The subdomain structure looks normal."

    @log_call
    def check_url_params(self, url: str) -> str:
        """
        Analyzes the query parameters of the given URL to detect suspicious parameters.

        :param url: The URL to analyze.
        :type url: str
        :return: A warning if suspicious or excessive parameters are found, otherwise a confirmation message.
        :rtype: str
        """
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        if len(query_params) > 3:
            return f"⚠️ WARNING: The URL has too many parameters ({len(query_params)})."
        for key in query_params.keys():
            if key.lower() in self.suspicious_keys:
                return f"⚠️ WARNING: The URL contains a suspicious parameter: {key}"
        return "✅ The URL parameters seem normal."

    @log_call
    def check_shortened_url(self, url: str) -> str:
        """
        Checks if the given URL uses a known link shortener service.

        :param url: The URL to check.
        :type url: str
        :return: A warning if the URL is shortened, otherwise a confirmation message.
        :rtype: str
        """
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}"
        if domain in self.shorteners:
            return f"⚠️ WARNING: The URL uses a link shortener ({domain}). It may hide a malicious site!"
        return "✅ The URL is not shortened."

    @log_call
    def check_url_length(self, url: str) -> str:
        """
        Checks if the given URL is excessively long.

        :param url: The URL to check.
        :type url: str
        :return: A warning if the URL is very long, otherwise a confirmation message.
        :rtype: str
        """
        if len(url) > 100:
            return f"⚠️ WARNING: The URL is very long ({len(url)} characters). It might be obfuscating something."
        return "✅ The URL length is normal."

    @log_call
    def check_suspicious_words(self, url: str) -> str:
        """
        Checks if the given URL contains suspicious words commonly used in phishing attempts.

        :param url: The URL to analyze.
        :type url: str
        :return: A warning if suspicious words are detected, otherwise a confirmation message.
        :rtype: str
        """
        for word in self.suspicious_words:
            if re.search(rf"\b{word}\b", url, re.IGNORECASE):
                return f"⚠️ WARNING: The URL contains the suspicious word '{word}'"
        return "✅ No suspicious words detected."

    @log_call
    def check_url_safety(self, url: str) -> str:
        """
        Checks if the given URL is unsafe using the Google Safe Browsing API.

        :param url: The URL to check.
        :type url: str
        :return: A warning if the URL is unsafe, otherwise a confirmation message.
        :rtype: str
        """
        payload = {
            "client": {
                "clientId": "phishing-detector",
                "clientVersion": "1.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        response = requests.post(self.safe_browsing_url, json=payload)
        if response.status_code == 200:
            data = response.json()
            if "matches" in data:
                return f"⚠️ WARNING: The URL {url} is unsafe!"
            return f"✅ The URL {url} is not in Google's threat list."
        else:
            return f"❌ API Error: {response.text}"

    def analyze_url(self, url: str) -> None:
        """
        Performs a detailed analysis of the given URL and logs a professional risk assessment,
        including a final conclusion with the risk level.

        :param url: The URL to analyze.
        :type url: str
        :return: None
        :rtype: None
        """
        separator = "=" * 80
        self.logger.info("\n%s\nStarting analysis for URL: %s\n%s", separator, url, separator)
        total_risk = 0
        details = []

        checks = [
            self.check_domain,
            self.check_subdomain,
            self.check_url_params,
            self.check_shortened_url,
            self.check_url_length,
            self.check_suspicious_words,
            self.check_url_safety
        ]

        for check in checks:
            result = check(url)
            if "⚠️ WARNING" in result or "❌" in result:
                self.logger.warning(result)
            else:
                self.logger.info(result)
            if "⚠️ WARNING" in result:
                if check in [self.check_domain, self.check_url_safety]:
                    total_risk += 3
                elif check in [self.check_shortened_url, self.check_suspicious_words]:
                    total_risk += 2
                else:
                    total_risk += 1
                details.append(result)

        if total_risk == 0:
            risk_level, risk_msg = "RISK_LOW", "🟢 Low Risk: The URL appears safe."
        elif total_risk <= 3:
            risk_level, risk_msg = "RISK_MODERATE", "🟡 Moderate Risk: Some elements seem unusual, proceed with caution."
        elif total_risk <= 6:
            risk_level, risk_msg = "RISK_HIGH", "🟠 High Risk: Several suspicious elements detected! Be very careful."
        else:
            risk_level, risk_msg = "RISK_CRITICAL", "🔴 CRITICAL RISK: This URL is highly suspicious! Possible phishing attempt."

        self.logger.info("\n%s\nFinal Risk Analysis for URL: %s", separator, url)
        if risk_level in ["RISK_HIGH", "RISK_CRITICAL"]:
            self.logger.warning("%s - %s", risk_level, risk_msg)
        else:
            self.logger.info("%s - %s", risk_level, risk_msg)

        self.logger.info("Detailed findings:")
        for detail in details:
            self.logger.warning(" - %s", detail)
        self.logger.info("%s\n", separator)

        if risk_level in ["RISK_HIGH", "RISK_CRITICAL"]:
            self.logger.warning("Conclusion: Analysis complete for URL: %s - %s", url, risk_msg)
        else:
            self.logger.info("Conclusion: Analysis complete for URL: %s - %s", url, risk_msg)

    def analyze_urls_from_file(self, filename: str) -> None:
        """
        Reads URLs from a file and analyzes each one.

        :param filename: The name of the file containing URLs.
        :type filename: str
        :return: None
        :rtype: None
        """
        try:
            with open(filename, "r") as file:
                for url in file:
                    self.analyze_url(url.strip())
        except FileNotFoundError:
            self.logger.error("❌ ERROR: The file '%s' was not found.", filename)
