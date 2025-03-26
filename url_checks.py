import re
import requests
import tldextract
import logging
import functools
import json
from urllib.parse import urlparse, parse_qs
from config import Config
from logger_config import setup_logger


def log_call(func):
    """
    A simple decorator that preserves the function's __name__ for logging purposes.
    It does not add additional logging.

    :param func: The function to decorate.
    :type func: function
    :return: The wrapped function.
    :rtype: function
    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    return wrapper


def normalize_url(url: str) -> str:
    """
    Normalizes a URL by stripping whitespace, converting to lowercase, and removing a trailing slash.

    :param url: The URL to normalize.
    :type url: str
    :return: The normalized URL.
    :rtype: str
    """
    return url.strip().lower().rstrip("/")


class URLAnalyzer:
    """
    A class to perform phishing detection and URL analysis.

    In addition to standard checks (domain, subdomain, URL parameters, etc.),
    this class verifies if the complete URL is present in the local bad URLs list defined in the configuration.
    """

    def __init__(self):
        """
        Initializes the URLAnalyzer instance, loads configuration constants, and sets up a dedicated logger instance.
        Also loads the bad URLs list from the configuration.
        """
        self.logger = logging.getLogger(f"phishing_detector.{self.__class__.__name__}")
        config = Config()
        self.api_key = config.API_KEY
        self.safe_browsing_url = config.SAFE_BROWSING_URL
        self.trusted_domains = config.TRUSTED_DOMAINS
        self.suspicious_keys = config.SUSPICIOUS_KEYS
        self.shorteners = config.SHORTENERS
        self.suspicious_words = config.SUSPICIOUS_WORDS
        self.bad_urls = config.BAD_URL  # List of complete bad URLs from config.py

    @log_call
    def check_domain(self, url: str) -> str:
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}"
        if domain in self.trusted_domains:
            return f"✅ The domain {domain} is trusted."
        return f"⚠️ WARNING: The domain {domain} is not in the trusted list!"

    @log_call
    def check_subdomain(self, url: str) -> str:
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}"
        subdomain = extracted.subdomain
        if domain in self.trusted_domains and subdomain:
            return (f"⚠️ WARNING: The URL uses a suspicious subdomain ({subdomain}). "
                    f"It may be trying to impersonate {domain}!")
        return "✅ The subdomain structure looks normal."

    @log_call
    def check_url_params(self, url: str) -> str:
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
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}"
        if domain in self.shorteners:
            return f"⚠️ WARNING: The URL uses a link shortener ({domain}). It may hide a malicious site!"
        return "✅ The URL is not shortened."

    @log_call
    def check_url_length(self, url: str) -> str:
        if len(url) > 100:
            return f"⚠️ WARNING: The URL is very long ({len(url)} characters). It might be obfuscating something."
        return "✅ The URL length is normal."

    @log_call
    def check_suspicious_words(self, url: str) -> str:
        for word in self.suspicious_words:
            if re.search(rf"\b{word}\b", url, re.IGNORECASE):
                return f"⚠️ WARNING: The URL contains the suspicious word '{word}'"
        return "✅ No suspicious words detected."

    @log_call
    def check_url_safety(self, url: str) -> str:
        """
        Checks if the given URL is unsafe using the Google Safe Browsing API.
        For testing purposes, the actual API call is commented out.
        """
        # --- BEGIN Google API Call (commented for testing) ---
        # payload = {
        #     "client": {
        #         "clientId": "phishing-detector",
        #         "clientVersion": "1.0"
        #     },
        #     "threatInfo": {
        #         "threatTypes": [
        #             "MALWARE",
        #             "SOCIAL_ENGINEERING",
        #             "UNWANTED_SOFTWARE",
        #             "POTENTIALLY_HARMFUL_APPLICATION"
        #         ],
        #         "platformTypes": ["ANY_PLATFORM"],
        #         "threatEntryTypes": ["URL"],
        #         "threatEntries": [{"url": url}]
        #     }
        # }
        # response = requests.post(self.safe_browsing_url, json=payload)
        # if response.status_code == 200:
        #     data = response.json()
        #     if "matches" in data:
        #         return f"⚠️ WARNING: The URL {url} is unsafe!"
        #     return f"✅ The URL {url} is not in Google's threat list."
        # else:
        #     return f"❌ API Error: {response.text}"
        # --- END Google API Call ---
        return f"✅ Test mode: The URL {url} is assumed safe (Google API disabled)."

    @log_call
    def check_bad_urls(self, url: str) -> str:
        """
        Checks if the given complete URL is present in the local bad URLs list from the configuration.
        The comparison is done after normalizing the URL (trimming, converting to lowercase, and removing trailing slashes).
        """
        normalized_url = normalize_url(url)
        normalized_bad = [normalize_url(bad) for bad in self.bad_urls]
        if normalized_url in normalized_bad:
            return "⚠️ WARNING: The URL is found in the local bad URLs list."
        else:
            return "✅ The URL is not found in the local bad URLs list."

    def analyze_url(self, url: str) -> None:
        """
        Performs a detailed analysis of the given URL and logs a professional risk assessment,
        including the local bad URLs check.
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
            self.check_url_safety,
            self.check_bad_urls
        ]

        for check in checks:
            result = check(url)
            # Add the name of the function to the log message
            log_message = f"{check.__name__} - {result}"
            if "⚠️ WARNING" in result or "❌" in result:
                self.logger.warning(log_message)
            else:
                self.logger.info(log_message)
            if "⚠️ WARNING" in result:
                if check.__name__ == "check_bad_urls":
                    total_risk += 7
                elif check.__name__ in ["check_domain", "check_url_safety"]:
                    total_risk += 3
                elif check.__name__ in ["check_shortened_url", "check_suspicious_words"]:
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

        # Adding a newline before the conclusion for better visual separation.
        if risk_level in ["RISK_HIGH", "RISK_CRITICAL"]:
            self.logger.warning("\nConclusion: Analysis complete for URL: %s - %s", url, risk_msg)
        else:
            self.logger.info("\nConclusion: Analysis complete for URL: %s - %s", url, risk_msg)

    def analyze_urls_from_file(self, filename: str) -> None:
        """
        Reads URLs from a file and analyzes each one.
        """
        try:
            with open(filename, "r") as file:
                for url in file:
                    self.analyze_url(url.strip())
        except FileNotFoundError:
            self.logger.error("❌ ERROR: The file '%s' was not found.", filename)
