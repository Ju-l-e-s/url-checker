import os
import json
from pathlib import Path
from dotenv import load_dotenv
from typing import List

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

class Config:
    """
    Contains configuration constants for the phishing detector.

    The lists for trusted domains, suspicious keys, URL shorteners, suspicious words, and bad URLs
    are loaded from external JSON files (if available) to facilitate updates and maintainability.
    """
    API_KEY: str = os.getenv("API_KEY")
    if not API_KEY:
        raise ValueError("API_KEY not found. Ensure a .env file with API_KEY=your_key is present.")

    SAFE_BROWSING_URL: str = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"

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
    BAD_URL: List[str] = load_list_from_file("bad_urls.json")
