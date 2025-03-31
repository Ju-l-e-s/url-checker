# URL Analyzer

A Python command-line tool for analyzing URLs to detect potential security threats such as phishing attempts, typosquatting, suspicious domains, and other malicious patterns.

## Features

- Domain verification against trusted domains
- Subdomain analysis
- TLD (Top-Level Domain) verification
- URL parameters scanning
- Link shortener detection
- URL length analysis
- Suspicious words detection
- Google Safe Browsing API integration (disabled in test mode)
- Known bad URLs database checking
- Typosquatting detection
- SSL certificate verification
- Suspicious URL patterns matching
- Comprehensive risk scoring system

## Requirements

- Python 3.6+
- Required packages: requests, tldextract, python-dotenv

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/url-analyzer.git
   cd url-analyzer
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. (Optional) Set up your Google Safe Browsing API key in a `.env` file:
   ```
   API_KEY=your_google_api_key_here
   ```

## Usage

```
python main.py [-h] (-u URL | -f FILE | -t) [-o OUTPUT] [-v]
```

### Arguments:

- `-u, --url URL`: Analyze a single URL
- `-f, --file FILE`: Analyze URLs from a file (one URL per line)
- `-t, --test`: Run analysis on pre-defined test URLs
- `-o, --output OUTPUT`: Save results to a JSON file
- `-v, --verbose`: Enable verbose output for detailed logging

### Examples:

Analyze a single URL:
```
python main.py -u https://example.com -v
```

Analyze URLs from a file:
```
python main.py -f urls.txt -o results.json
```

Run tests:
```
python main.py -t -v
```

## URL Feeds

The tool includes a separate script (`update_feeds.py`) to fetch and update the list of known malicious URLs from various threat intelligence feeds:

- OpenPhish
- URLhaus
- PhishTank (requires API key)

Run the following to update your local bad URLs database:
```
python update_feeds.py
```

## Configuration

The tool's behavior can be customized by modifying or creating the following JSON files:

- `trusted_domains.json`: List of trusted domains
- `suspicious_keys.json`: Suspicious URL parameter names
- `shorteners.json`: Known URL shortener domains
- `suspicious_words.json`: Words commonly found in malicious URLs
- `suspicious_tlds.json`: TLDs frequently used for malicious domains
- `suspicious_url_patterns.json`: Regex patterns for suspicious URLs
- `bad_urls.json`: Known malicious URLs
- `risk_coefficients.json`: Risk weights for different checks
- `risk_thresholds.json`: Thresholds for risk level categories
