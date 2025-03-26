from logger_config import setup_logger
from url_checks import URLAnalyzer
import argparse
import sys
import os
import datetime


def main():
    """

    main function for the phishing-detector CLI tool that analyzes URLs for potential phishing attempts.
    It can analyze a single URL, a file containing URLs, or a test URL file.

    :param: None
    :return: None
    :rtype: None
    """
    parser = argparse.ArgumentParser(
        description='Phishing URL Detector - Analyzes URLs for potential phishing attempts')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--url', help='URL to analyze')
    group.add_argument('-f', '--file', help='File containing URLs to analyze (one per line)')
    group.add_argument('-t', '--test', action='store_true', help='Run analysis on test URLs')
    parser.add_argument('-o', '--output', help='Output JSON file for results')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    args = parser.parse_args()

    # Setup logger
    setup_logger(verbose=args.verbose)
    analyzer = URLAnalyzer()

    # Create a default output file name if not specified
    output_file = args.output
    if not output_file and (args.file or args.test):
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"phishing_analysis_{timestamp}.json"

    # Argument-based analysis
    if args.url:
        print(f"\nAnalyzing URL: {args.url}")
        analyzer.analyze_url(args.url)
        if output_file:
            results = [analyzer.get_risk_summary(args.url)]
            analyzer.export_results_to_json(results, output_file)
            print(f"\nResults exported to {output_file}")

    elif args.file:
        if not os.path.exists(args.file):
            print(f"Error: File {args.file} not found.")
            sys.exit(1)

        print(f"\nAnalyzing URLs from file: {args.file}")
        results = analyzer.analyze_urls_from_file(args.file)

        if output_file:
            analyzer.export_results_to_json(results, output_file)
            print(f"\nResults exported to {output_file}")

    elif args.test:
        test_urls = [
            "http://tamanna800.github.io/amazon",
            "https://drive.google.com/uc?export=download&id=1UnU9ydYXvBsgDAS_xzEWlzcaiV6O_QdT",
            "https://secure-paypal.com/verify-account?user=martin&password=password",
            "https://secure-paypa1.com/",
            "https://bit.ly/3abcxyz",
            "https://google.com",
            "http://192.168.1.1/admin",
            "https://amazon-account-verification.xyz/login",
            "https://paypa1.com/secure",
            "https://www.g00gle.com/search",
            "https://drive-google.com.malicious.site/document",
            "https://bank-secure-login.cf/login?redirect=https://bank.com"
        ]

        print(f"\nRunning analysis on {len(test_urls)} test URLs...")
        results = []
        for url in test_urls:
            print(f"\nAnalyzing test URL: {url}")
            analyzer.analyze_url(url)
            results.append(analyzer.get_risk_summary(url))

        if output_file:
            analyzer.export_results_to_json(results, output_file)
            print(f"\nTest results exported to {output_file}")


if __name__ == "__main__":
    main()