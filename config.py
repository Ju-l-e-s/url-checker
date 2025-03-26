import os
import json
from pathlib import Path
from dotenv import load_dotenv
from typing import List, Dict, Any

# Load environment variables
load_dotenv()


def load_list_from_file(filename: str, default: List[str] = None) -> List[str]:
    """
    Loads a list from a JSON file if it exists and is valid; otherwise returns the default list.
    If the JSON file is a dictionary containing a key "urls", that list is returned.

    :param filename: The JSON file to load.
    :type filename: str
    :param default: The default list to use if the file is missing or invalid (defaults to an empty list).
    :type default: List[str] or None
    :return: The loaded list or the default.
    :rtype: List[str]
    """
    if default is None:
        default = []
    filepath = Path(filename)
    if filepath.exists():
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    return data
                elif isinstance(data, dict) and "urls" in data and isinstance(data["urls"], list):
                    return data["urls"]
        except Exception as e:
            print(f"Warning: Could not load {filename}: {e}")
    return default


def load_dict_from_file(filename: str, default: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Loads a dictionary from a JSON file if it exists and is valid; otherwise returns the default dict.

    :param filename: The JSON file to load.
    :type filename: str
    :param default: The default dict to use if the file is missing or invalid.
    :type default: Dict[str, Any] or None
    :return: The loaded dict or the default.
    :rtype: Dict[str, Any]
    """
    if default is None:
        default = {}
    filepath = Path(filename)
    if filepath.exists():
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
        except Exception as e:
            print(f"Warning: Could not load {filename}: {e}")
    return default


class Config:
    """
    Contains configuration constants for the phishing detector.

    The lists for trusted domains, suspicious keys, URL shorteners, suspicious words, and bad URLs
    are loaded from external JSON files (if available) to facilitate updates and maintainability.
    """
    API_KEY: str = os.getenv("API_KEY")
    if not API_KEY:
        # for development, if API_KEY is not set, use a test key
        API_KEY = "test_api_key"
        print("Warning: API_KEY not found. Using test key for development.")

    SAFE_BROWSING_URL: str = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"

    # Charger les listes à partir des fichiers JSON
    TRUSTED_DOMAINS: List[str] = load_list_from_file(
        "trusted_domains.json",
        ["paypal.com", "google.com", "amazon.com", "facebook.com"]
    )

    SUSPICIOUS_KEYS: List[str] = load_list_from_file(
        "suspicious_keys.json",
        ["password", "secure", "login", "verify", "auth", "token", "download"]
    )

    SHORTENERS: List[str] = load_list_from_file(
        "shorteners.json",
        ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "shorte.st"]
    )

    SUSPICIOUS_WORDS: List[str] = load_list_from_file(
        "suspicious_words.json",
        ["secure", "verify", "update", "account", "login", "bank", "confirm"]
    )

    SUSPICIOUS_TLDS: List[str] = load_list_from_file(
        "suspicious_tlds.json",
        ["xyz", "top", "club", "online", "site", "website", "pw", "buzz", "icu"]
    )

    URL_SUSPICIOUS_PATTERNS: Dict[str, str] = load_dict_from_file(
        "suspicious_url_patterns.json",
        {"ip_address": r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"}
    )

    BAD_URL: List[str] = load_list_from_file("bad_urls.json", [])

    # Risk coefficients for each type of verification
    RISK_COEFFICIENTS: Dict[str, int] = load_dict_from_file(
        "risk_coefficients.json",
        {
            "check_domain": 3,
            "check_subdomain": 2,
            "check_url_params": 1,
            "check_shortened_url": 2,
            "check_url_length": 1,
            "check_suspicious_words": 2,
            "check_url_safety": 3,
            "check_bad_urls": 7,
            "check_tld": 2,
            "check_suspicious_pattern": 2,
            "check_typosquatting": 3,
            "check_ssl": 2,
            "check_redirect": 3
        }
    )

    # Risk thresholds
    RISK_THRESHOLDS: Dict[str, Dict[str, Any]] = load_dict_from_file(
        "risk_thresholds.json",
        {
            "RISK_LOW": {"max": 2, "color": "🟢", "message": "Low Risk: The URL appears safe."},
            "RISK_MODERATE": {"max": 5, "color": "🟡",
                              "message": "Moderate Risk: Some elements seem unusual, proceed with caution."},
            "RISK_HIGH": {"max": 10, "color": "🟠",
                          "message": "High Risk: Several suspicious elements detected! Be very careful."},
            "RISK_CRITICAL": {"max": float('inf'), "color": "🔴",
                              "message": "CRITICAL RISK: This URL is highly suspicious! Possible phishing attempt."}
        }
    )