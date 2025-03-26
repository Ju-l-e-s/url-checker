import re
import requests
import tldextract
import logging
import functools
import json
import ssl
import socket
import datetime
from urllib.parse import urlparse, parse_qs
from difflib import SequenceMatcher
from config import Config
from typing import Dict, Tuple, List, Any


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


def levenshtein_distance(s1: str, s2: str) -> int:
    """
    Calculate the Levenshtein distance (edit distance) between two strings.

    :param s1: First string
    :param s2: Second string
    :return: The edit distance between s1 and s2
    """
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)

    # len(s1) >= len(s2)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def similarity_ratio(s1: str, s2: str) -> float:
    """
    Calculate the similarity ratio between two strings using SequenceMatcher.

    :param s1: First string
    :param s2: Second string
    :return: Similarity ratio between 0 and 1
    """
    return SequenceMatcher(None, s1, s2).ratio()


class URLAnalyzer:
    """
    A class to perform phishing detection and URL analysis.

    Analyzes URLs for potential phishing attempts using multiple detection methods:
    - Domain verification against trusted domains
    - Subdomain analysis
    - TLD verification
    - URL parameters scanning
    - Link shortener detection
    - URL length analysis
    - Suspicious words detection
    - Google Safe Browsing API check
    - Known bad URLs database check
    - Typosquatting detection
    - SSL certificate verification
    - Suspicious URL patterns matching
    - Redirect analysis
    """

    def __init__(self):
        """
        Initializes the URLAnalyzer instance, loads configuration constants, and sets up a dedicated logger instance.
        Also loads the bad URLs list from the configuration.
        """
        self.logger = logging.getLogger(
            f"phishing_detector.{self.__class__.__name__}")
        config = Config()
        self.api_key = config.API_KEY
        self.safe_browsing_url = config.SAFE_BROWSING_URL
        self.trusted_domains = config.TRUSTED_DOMAINS
        self.suspicious_keys = config.SUSPICIOUS_KEYS
        self.shorteners = config.SHORTENERS
        self.suspicious_words = config.SUSPICIOUS_WORDS
        self.suspicious_tlds = config.SUSPICIOUS_TLDS
        self.url_suspicious_patterns = config.URL_SUSPICIOUS_PATTERNS
        self.bad_urls = config.BAD_URL
        self.risk_coefficients = config.RISK_COEFFICIENTS
        self.risk_thresholds = config.RISK_THRESHOLDS

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
            # Vérification des sous-domaines suspects pour les domaines de confiance
            suspicious_subdomains = ["secure", "security", "login", "signin", "account",
                                     "verify", "validation", "update", "service", "support",
                                     "confirm", "banking", "payment", "alert", "info"]

            for suspicious in suspicious_subdomains:
                if suspicious in subdomain.lower():
                    return (f"⚠️ WARNING: The URL uses a suspicious subdomain ({subdomain}). "
                            f"It may be trying to impersonate {domain}!")

            # Vérification des sous-domaines excessivement longs
            if len(subdomain) > 30:
                return (f"⚠️ WARNING: The subdomain ({subdomain}) is unusually long. "
                        f"This could be an attempt to hide malicious intent.")

            # Vérification des sous-domaines avec des caractères inhabituels
            if re.search(r"[^a-zA-Z0-9\-\.]", subdomain):
                return (f"⚠️ WARNING: The subdomain ({subdomain}) contains unusual characters. "
                        f"This could be an attempt to trick users.")

        return "✅ The subdomain structure looks normal."

    @log_call
    def check_tld(self, url: str) -> str:
        extracted = tldextract.extract(url)
        if extracted.suffix in self.suspicious_tlds:
            return f"⚠️ WARNING: The TLD '{extracted.suffix}' is commonly used in phishing campaigns."
        return f"✅ The TLD '{extracted.suffix}' is not in the suspicious list."

    @log_call
    def check_url_params(self, url: str) -> str:
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)

        # Check for the number of parameters
        if len(query_params) > 5:
            return f"⚠️ WARNING: The URL has too many parameters ({len(query_params)})."

        # Check for suspicious parameters
        for key in query_params.keys():
            if key.lower() in self.suspicious_keys:
                return f"⚠️ WARNING: The URL contains a suspicious parameter: {key}"

        # Check for long values in parameters
        for key, values in query_params.items():
            for value in values:
                if len(value) > 100:
                    return f"⚠️ WARNING: The URL parameter '{key}' has a very long value ({len(value)} characters)."

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
        suspicious_found = []
        url_lower = url.lower()

        for word in self.suspicious_words:
            if re.search(rf"\b{re.escape(word)}\b", url_lower):
                suspicious_found.append(word)

        if suspicious_found:
            if len(suspicious_found) == 1:
                return f"⚠️ WARNING: The URL contains the suspicious word '{suspicious_found[0]}'"
            elif len(suspicious_found) <= 3:
                words_str = "', '".join(suspicious_found)
                return f"⚠️ WARNING: The URL contains multiple suspicious words: '{words_str}'"
            else:
                return f"⚠️ WARNING: The URL contains {len(suspicious_found)} suspicious words!"

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

    @log_call
    def check_typosquatting(self, url: str) -> str:
        """
        Detects typosquatting attempts by comparing the domain
        to a list of trusted domains, with special attention
        to common character substitutions.
        """
        extracted = tldextract.extract(url)
        domain_name = extracted.domain

        # Dictionary of common substitutions used in typosquatting
        common_substitutions = {
            'o': '0',
            'l': '1',
            'i': '1',
            'e': '3',
            'a': '4',
            's': '5',
            'g': '9',
            'b': '8',
            't': '7'
        }

        # 1. Check for common substitutions
        for trusted in self.trusted_domains:
            trusted_extract = tldextract.extract(trusted)
            trusted_domain = trusted_extract.domain

            # Check for character substitutions
            for char, substitute in common_substitutions.items():
                if char in trusted_domain:
                    # Create a modified version of the trusted domain with the substitution
                    modified_domain = trusted_domain.replace(char, substitute)
                    # If this modified version matches the analyzed domain
                    if modified_domain == domain_name:
                        return f"⚠️ WARNING: The domain '{domain_name}' uses character substitution from '{trusted_domain}'. Likely typosquatting!"

        # 2. Check for similarity and edit distance
        for trusted in self.trusted_domains:
            trusted_extract = tldextract.extract(trusted)
            trusted_domain = trusted_extract.domain

            # Calculate similarity between domains
            similarity = similarity_ratio(domain_name, trusted_domain)

            # If the domain is very similar but not identical
            if similarity > 0.75 and similarity < 1.0:
                distance = levenshtein_distance(domain_name, trusted_domain)

                # If the difference is 3 characters or less
                if distance <= 3:
                    return f"⚠️ WARNING: The domain '{domain_name}' looks very similar to trusted domain '{trusted_domain}'. Possible typosquatting!"

        # 3. Check for additions/deletions (prefixes/suffixes)
        for trusted in self.trusted_domains:
            trusted_extract = tldextract.extract(trusted)
            trusted_domain = trusted_extract.domain

            # Check if the legitimate domain is contained in the suspect domain
            if trusted_domain in domain_name and trusted_domain != domain_name:
                # Calculate the length of added characters
                added_chars = len(domain_name) - len(trusted_domain)
                if added_chars <= 3:
                    return f"⚠️ WARNING: The domain '{domain_name}' contains the trusted domain '{trusted_domain}' with {added_chars} additional characters. Possible typosquatting!"

            # Check if the suspect domain is contained in the legitimate domain
            elif domain_name in trusted_domain and trusted_domain != domain_name:
                # Calculate the length of removed characters
                removed_chars = len(trusted_domain) - len(domain_name)
                if removed_chars <= 2:
                    return f"⚠️ WARNING: The domain '{domain_name}' is a shortened version of trusted domain '{trusted_domain}'. Possible typosquatting!"

        return "✅ No typosquatting detected."

    @log_call
    def check_ssl(self, url: str) -> str:
        """
        Check if the website uses HTTPS and try to verify the SSL certificate.
        """
        parsed_url = urlparse(url)

        # Check if the website uses HTTPS
        if parsed_url.scheme != "https":
            return "⚠️ WARNING: The website is not using HTTPS!"

        # For checking the certificate, this part would normally be enabled
        # for production use
        """
        try:
            hostname = parsed_url.netloc
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    # Check if the certificate is valide
                    if not cert:
                        return "⚠️ WARNING: Invalid SSL certificate!"
        except Exception as e:
            return f"⚠️ WARNING: SSL certificate verification failed: {str(e)}"
        """

        return "✅ The website uses HTTPS."

    @log_call
    def check_suspicious_pattern(self, url: str) -> str:
        """
        Checks if the URL matches suspicious patterns defined by regular expressions.
        """
        for pattern_name, pattern in self.url_suspicious_patterns.items():
            if re.search(pattern, url):
                return f"⚠️ WARNING: The URL matches a suspicious pattern ({pattern_name})."

        return "✅ No suspicious URL patterns detected."

    @log_call
    def check_redirect(self, url: str) -> str:
        """
        Checks if the URL redirects to another destination.
        Note: This function is commented out because it makes network requests
        which could slow down the analysis or cause security problems.
        """
        """
        try:
            response = requests.head(url, allow_redirects=False, timeout=5)
            if response.status_code in (301, 302, 303, 307, 308):
                redirect_url = response.headers.get('Location', '')
                if redirect_url:
                    # On pourrait faire une analyse du redirect_url ici
                    # ou simplement le signaler comme un risque potentiel
                    return f"⚠️ WARNING: The URL redirects to: {redirect_url}"
        except Exception as e:
            return f"⚠️ WARNING: Could not check redirects: {str(e)}"
        """
        return "✅ Test mode: Redirect check is disabled."

    def analyze_url(self, url: str) -> None:
        """
        Performs a detailed analysis of the given URL and logs a professional risk assessment,
        including multiple security checks for comprehensive phishing detection.
        """
        separator = "=" * 80
        self.logger.info(
            "\n%s\nStarting analysis for URL: %s\n%s", separator, url, separator)
        total_risk = 0
        details = []
        # Full list of checks to perform
        checks = [
            self.check_domain,
            self.check_subdomain,
            self.check_tld,
            self.check_url_params,
            self.check_shortened_url,
            self.check_url_length,
            self.check_suspicious_words,
            self.check_suspicious_pattern,
            self.check_url_safety,
            self.check_bad_urls,
            self.check_typosquatting,
            self.check_ssl,
            self.check_redirect
        ]

        for check in checks:
            result = check(url)
            # Add the name of the function to the log message
            log_message = f"{check.__name__} - {result}"
            if "⚠️ WARNING" in result or "❌" in result:
                self.logger.warning(log_message)
            else:
                self.logger.info(log_message)

            # Use the risk coefficients from the configuration
            if "⚠️ WARNING" in result:
                risk_value = self.risk_coefficients.get(
                    check.__name__, 1)
                total_risk += risk_value
                details.append(result)

        # Determine the risk level based on the configured thresholds
        risk_level = "RISK_LOW"
        for level, threshold_data in sorted(self.risk_thresholds.items(),
                                            key=lambda x: x[1]["max"]):
            if total_risk <= threshold_data["max"]:
                risk_level = level
                risk_msg = f"{threshold_data['color']} {threshold_data['message']}"
                break

        self.logger.info(
            "\n%s\nFinal Risk Analysis for URL: %s", separator, url)
        if risk_level in ["RISK_HIGH", "RISK_CRITICAL"]:
            self.logger.warning("%s - %s", risk_level, risk_msg)
        else:
            self.logger.info("%s - %s", risk_level, risk_msg)

        self.logger.info("Detailed findings:")
        for detail in details:
            self.logger.warning(" - %s", detail)
        self.logger.info("%s\n", separator)

        # Additional information about the analysis
        self.logger.info("Analysis Summary:")
        self.logger.info(" - Total Risk Score: %d", total_risk)
        self.logger.info(" - Total Checks Performed: %d", len(checks))
        self.logger.info(" - Issues Found: %d", len(details))

        # Recommendations based on the risk level
        self.logger.info("\nRecommendations:")
        if risk_level == "RISK_LOW":
            self.logger.info(" - The URL appears safe to visit.")
        elif risk_level == "RISK_MODERATE":
            self.logger.info(
                " - Proceed with caution and verify the source of this URL.")
            self.logger.info(
                " - Check the website's SSL certificate before entering any information.")
        elif risk_level == "RISK_HIGH":
            self.logger.warning(
                " - Be very careful with this URL. It shows multiple suspicious elements.")
            self.logger.warning(
                " - Do not enter any personal information or credentials.")
            self.logger.warning(
                " - Consider reporting this URL to phishing databases if confirmed malicious.")
        else:  # RISK_CRITICAL
            self.logger.warning(
                " - DO NOT visit this URL! It is likely a phishing attempt.")
            self.logger.warning(
                " - Report this URL to phishing databases and security teams.")
            self.logger.warning(
                " - If you've already visited it, scan your device for malware.")

        # Adding a newline before the conclusion for better visual separation.
        if risk_level in ["RISK_HIGH", "RISK_CRITICAL"]:
            self.logger.warning(
                "\nConclusion: Analysis complete for URL: %s - %s", url, risk_msg)
        else:
            self.logger.info(
                "\nConclusion: Analysis complete for URL: %s - %s", url, risk_msg)

    def get_risk_summary(self, url: str) -> Dict[str, Any]:
        """
        Performs an analysis of the URL and returns a summary dictionary with risk information.
        Useful for integrating with other applications or creating reports.

        :param url: The URL to analyze.
        :return: A dictionary containing risk assessment results.
        """
        total_risk = 0
        details = []
        check_results = {}

        # Checking list to perform
        checks = [
            self.check_domain,
            self.check_subdomain,
            self.check_tld,
            self.check_url_params,
            self.check_shortened_url,
            self.check_url_length,
            self.check_suspicious_words,
            self.check_suspicious_pattern,
            self.check_url_safety,
            self.check_bad_urls,
            self.check_typosquatting,
            self.check_ssl,
            self.check_redirect
        ]

        for check in checks:
            result = check(url)
            check_results[check.__name__] = result

            if "⚠️ WARNING" in result:
                risk_value = self.risk_coefficients.get(check.__name__, 1)
                total_risk += risk_value
                details.append(result)

        # Determining the risk level
        risk_level = "RISK_LOW"
        risk_msg = ""
        risk_color = "🟢"

        for level, threshold_data in sorted(self.risk_thresholds.items(),
                                            key=lambda x: x[1]["max"]):
            if total_risk <= threshold_data["max"]:
                risk_level = level
                risk_msg = threshold_data["message"]
                risk_color = threshold_data["color"]
                break

        # Create a summary dictionary
        summary = {
            "url": url,
            "risk_score": total_risk,
            "risk_level": risk_level,
            "risk_message": risk_msg,
            "risk_color": risk_color,
            "issues_found": len(details),
            "issues_details": details,
            "check_results": check_results,
            "timestamp": datetime.datetime.now().isoformat()
        }

        return summary

    def analyze_urls_from_file(self, filename: str) -> List[Dict[str, Any]]:
        """
        Reads URLs from a file and analyzes each one.

        :param filename: The file containing URLs to analyze, one per line.
        :return: A list of summary dictionaries for each URL analyzed.
        """
        results = []
        try:
            with open(filename, "r") as file:
                for url in file:
                    url = url.strip()
                    if url:  # ignore empty lines
                        self.analyze_url(url)
                        results.append(self.get_risk_summary(url))
            return results
        except FileNotFoundError:
            self.logger.error(
                "❌ ERROR: The file '%s' was not found.", filename)
            return []

    def export_results_to_json(self, results: List[Dict[str, Any]], output_file: str) -> None:
        """
        Exports analysis results to a JSON file.

        :param results: List of analysis summary dictionaries.
        :param output_file: The output file path.
        """
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump({
                    "analysis_date": datetime.datetime.now().isoformat(),
                    "total_urls_analyzed": len(results),
                    "results": results
                }, f, indent=4, ensure_ascii=False)
            self.logger.info(f"Results exported to {output_file}")
        except Exception as e:
            self.logger.error(
                f"❌ ERROR: Failed to export results to {output_file}: {str(e)}")
