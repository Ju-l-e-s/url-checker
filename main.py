import os
import requests
import json
from dotenv import load_dotenv
from typing import List, Dict, Optional

# Load environment variables
load_dotenv()
API_KEY = os.getenv("API_KEY")

if not API_KEY:
    raise ValueError("The API key is not found. Make sure you have a .env file with API_KEY=your_key")

URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + API_KEY

def check_url_safety(url: str) -> str:
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
            "threatTypes": [
                "MALWARE",  # Malicious sites that install viruses
                "SOCIAL_ENGINEERING",  # Phishing and fake alerts
                "UNWANTED_SOFTWARE",  # Unwanted programs (spyware, adware)
                "POTENTIALLY_HARMFUL_APPLICATION"  # Suspicious mobile apps
            ],
            "platformTypes": [
                "ANY_PLATFORM"  # Verification for all systems (Windows, Mac, Android...)
            ],
            "threatEntryTypes": [
                "URL"  # check URLs, not files
            ],
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

def check_domain(url: str) -> str:
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
# print(check_domain("https://paypa1.com/login"))  # Fake Paypal
# print(check_domain("https://google.com"))  # Google is safe


from urllib.parse import urlparse, parse_qs

# List of suspicious parameter names
SUSPICIOUS_KEYS = ["password", "secure", "login", "verify", "auth", "token"]

def check_url_params(url: str) -> str:
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
# print(check_url_params("https://example.com/login?user=john&password=1234"))  # password detected
# print(check_url_params("https://example.com/search?q=test"))  # ✅ Normal
# print(check_url_params("https://secure-bank.com/verify?auth=admin&token=xyz"))  # auth and token detected

SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "shorte.st"]

def check_shortened_url(url: str) -> str:
    """
    Checks if the given URL uses a known link shortener service.

    :param url: The URL to check
    :type url: str
    :return: A warning if the URL is shortened, otherwise a safe message
    :rtype: str
    """
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"

    if domain in SHORTENERS:
        return f"⚠️ WARNING: The URL uses a link shortener ({domain}). It may hide a malicious site!"

    return "✅ The URL is not shortened."


# Tests
# print(check_shortened_url("https://bit.ly/3abcxyz"))  # bit.ly detected
# print(check_shortened_url("https://example.com/page"))  # Normal

def check_url_length(url: str) -> str:
    """
    Checks if the given URL is excessively long.

    :param url: The URL to evaluate
    :type url: str
    :return: A warning if the URL is very long, otherwise a normal length message
    :rtype: str
    """
    if len(url) > 100:
        return f"⚠️ WARNING: The URL is very long ({len(url)} characters). It might be obfuscating something."

    return "✅ The URL length is normal."


# Tests
# print(check_url_length(
#     "https://example.com/secure/login/update/verify/details/user/account/info/confirm/password/1234567890/"))  # Long URL
# print(check_url_length("https://google.com"))  # Normal

import re

SUSPICIOUS_WORDS = ["secure", "verify", "update", "account", "login", "bank", "confirm"]

def check_suspicious_words(url: str) -> str:
    """
    Checks if the given URL contains suspicious words commonly used in phishing attempts.

    :param url: The URL to analyze
    :type url: str
    :return: A warning if suspicious words are found, otherwise a normal message
    :rtype: str
    """
    for word in SUSPICIOUS_WORDS:
        if re.search(rf"\\b{word}\\b", url, re.IGNORECASE):  # \\b ensures whole word match
            return f"⚠️ WARNING: The URL contains the suspicious word '{word}'"

    return "✅ No suspicious words detected."


# # Tests
# print(check_suspicious_words("https://secure-paypal.com/verify-account"))  # "secure", "verify"
# print(check_suspicious_words("https://example.com/home"))  # Normal

def analyze_url(url: str) -> None:
    """
    Create an  analysis of the given URL by checking multiple criteria:
    domain trust, suspicious parameters, link shorteners, URL length, suspicious words,
    and Google Safe Browsing results. Prints a final risk assessment.

    :param url: The URL to analyze
    :type url: str
    :return: None (prints the results of the analysis, including final risk score)
    :rtype: None
    """
    print("\n🔍 Analyzing:", url)
    total_risk = 0  # Total risk score
    details = []  # List of detected alerts

    # Check the domain
    result = check_domain(url)
    print(result)
    if "WARNING" in result:
        total_risk += 3  # High risk
        details.append(result)

    # Check URL parameters
    result = check_url_params(url)
    print(result)
    if "WARNING" in result:
        total_risk += 3  # High risk
        details.append(result)

    # Check URL shorteners
    result = check_shortened_url(url)
    print(result)
    if "WARNING" in result:
        total_risk += 2
        details.append(result)

    # Check the length of the URL
    result = check_url_length(url)
    print(result)
    if "WARNING" in result:
        total_risk += 1
        details.append(result)

    # Suspicious words detection
    result = check_suspicious_words(url)
    print(result)
    if "WARNING" in result:
        total_risk += 2
        details.append(result)

    # Check with Google Safe Browsing
    safe_browsing_result = check_url_safety(url)
    print(safe_browsing_result)
    if "WARNING" in safe_browsing_result:
        total_risk += 3
        details.append(safe_browsing_result)

    # Score-based conclusion
    print("\n📊 **Final Risk Analysis**:")
    if total_risk == 0:
        print("🟢 Low Risk: The URL appears safe.")
    elif total_risk <= 3:
        print("🟡 Moderate Risk: Be cautious, some elements seem unusual.")
    elif total_risk <= 6:
        print("🟠 High Risk: Several suspicious elements detected! Be very careful.")
    else:
        print("🔴 CRITICAL RISK: This URL is highly suspicious! Possible phishing attempt.")

    print("\n🛠 Details of the analysis:")
    for detail in details:
        print(" -", detail)

# Tests
analyze_url("https://secure-paypal.com/verify-account?user=martin&password=password")
analyze_url("https://secure-paypa1.com/")
analyze_url("https://bit.ly/3abcxyz")
analyze_url("https://google.com")