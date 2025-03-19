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
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"  # Get the main domain

    if domain in TRUSTED_DOMAINS:
        return f"✅ The domain {domain} is trusted."
    else:
        return f"⚠️ WARNING: The domain {domain} is not in the trusted list!"


# Tests
print(check_domain("https://paypa1.com/login"))  # Fake Paypal
print(check_domain("https://google.com"))  # Google is safe
