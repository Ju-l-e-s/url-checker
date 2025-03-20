import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class Config:
    """
    Contains configuration constants for the phishing detector.

    :param: None
    :return: None
    :rtype: None
    """
    API_KEY = os.getenv("API_KEY")
    if not API_KEY:
        raise ValueError("API_KEY not found. Ensure a .env file with API_KEY=your_key is present.")

    SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + API_KEY

    # Trusted domains list
    TRUSTED_DOMAINS = ["paypal.com", "google.com", "amazon.com", "facebook.com"]

    # Suspicious parameter names
    SUSPICIOUS_KEYS = ["password", "secure", "login", "verify", "auth", "token"]

    # Known URL shorteners
    SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "shorte.st"]

    # Phishing-related words
    SUSPICIOUS_WORDS = ["secure", "verify", "update", "account", "login", "bank", "confirm"]
