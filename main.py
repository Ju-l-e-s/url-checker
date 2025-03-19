import os
import requests
import json
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
API_KEY = os.getenv("API_KEY")

if not API_KEY:
    raise ValueError("The API key is not found. Make sure you have a .env file with API_KEY=your_key")

URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + API_KEY

def check_url_safety(url):
    """
    Checks if the given URL is classified as unsafe by Google Safe Browsing.

    :param url: The URL to check
    :type url: str
    :return: A warning message if the URL is unsafe, otherwise a confirmation of safety
    :rtype: str
    """
    payload = {
        "client": {
            "clientId": "phishing-detector",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    response = requests.post(URL, json=payload)

    if response.status_code == 200:
        data = response.json()
        if "matches" in data:
            return f"⚠️ WARNING: The URL {url} is unsafe!"
        return f"✅ The URL {url} is safe."
    else:
        return f"❌ API Error: {response.text}"


# Test with a suspicious URL
test_url = "http://malware.testing.google.test/testing/malware/"
# print(check_url_safety(test_url))

import tldextract

# Trusted domains list (can be improved)
TRUSTED_DOMAINS = ["paypal.com", "google.com", "amazon.com", "facebook.com"]

def check_domain(url):
    """
    Checks if the domain of a given URL is in the trusted domains list.

    :param url: The URL to extract the domain from
    :type url: str
    :return: A message indicating whether the domain is trusted
    :rtype: str
    """
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"  # Get the main domain
    if domain in TRUSTED_DOMAINS:
        return f"✅ The domain {domain} is trusted."
    else:
        return f"⚠️ WARNING: The domain {domain} is not in the trusted list!"


# Tests
print(check_domain("https://paypa1.com/login"))  # Fake Paypal
print(check_domain("https://google.com"))  # Google is safe


from urllib.parse import urlparse, parse_qs

# List of suspicious parameter names
SUSPICIOUS_KEYS = ["password", "secure", "login", "verify", "auth", "token"]

def check_url_params(url):
    """
    Analyzes the query parameters of a given URL to detect suspicious parameters.

    :param url: The URL to analyze
    :type url: str
    :return: A warning if suspicious parameters or excessive parameters are found, otherwise a safe message
    :rtype: str
    """
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)  # Get parameters as a dictionary

    # Check if there are too many parameters
    if len(query_params) > 3:
        return f"⚠️ WARNING: The URL has too many parameters ({len(query_params)})."

    # Check for suspicious keywords
    for key in query_params.keys():
        if key.lower() in SUSPICIOUS_KEYS:
            return f"⚠️ WARNING: The URL contains a suspicious parameter: {key}"

    return "✅ The URL parameters seem normal."

# Tests
print(check_url_params("https://example.com/login?user=john&password=1234"))  # password detected
print(check_url_params("https://example.com/search?q=test"))  # ✅ Normal
print(check_url_params("https://secure-bank.com/verify?auth=admin&token=xyz"))  # auth and token detected