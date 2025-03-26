import requests
import json
import csv
from io import StringIO, BytesIO
from datetime import datetime
from zipfile import ZipFile
import os


def fetch_openphish() -> list:
    """
    Fetches the OpenPhish feed of phishing URLs.

    :return: List of URLs from OpenPhish.
    :rtype: list
    """
    url = "https://openphish.com/feed.txt"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.text.splitlines()
        urls = [line.strip() for line in data if line.strip()]
        print(f"Successfully fetched OpenPhish: {len(urls)} URLs")
        return urls
    except Exception as e:
        print(f"Error fetching OpenPhish: {e}")
        return []


def fetch_urlhaus_online() -> list:
    """
    Fetches the URLHaus online JSON feed and extracts malicious URLs.

    The JSON response is a dictionary where each key is an entry ID and each value is a list of
    entry dictionaries.

    :return: List of URLs from URLHaus online feed.
    :rtype: list
    """
    url = "https://urlhaus.abuse.ch/downloads/json_online/"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        urls = []
        for entry_id, entries in data.items():
            for entry in entries:
                if "url" in entry and entry["url"]:
                    urls.append(entry["url"].strip())
        print(f"Successfully fetched URLHaus (online JSON): {len(urls)} URLs")
        return urls
    except Exception as e:
        print(f"Error fetching URLHaus (online JSON): {e}")
        return []


def fetch_phishtank() -> list:
    """
    Fetches the PhishTank JSON feed of phishing URLs.

    Note: PhishTank now requires an application key. Without it, this function returns an empty list.

    :return: List of URLs from PhishTank.
    :rtype: list
    """
    url = "https://data.phishtank.com/data/online-valid.json"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        urls = []
        for entry in data:
            if "url" in entry and entry["url"]:
                urls.append(entry["url"].strip())
        print(f"Successfully fetched PhishTank: {len(urls)} URLs")
        return urls
    except Exception as e:
        print(f"Error fetching PhishTank: {e}")
        return []


def aggregate_feeds() -> list:
    """
    Aggregates phishing URLs from multiple feeds and removes duplicates.

    :return: A list of unique phishing URLs.
    :rtype: list
    """
    openphish_urls = fetch_openphish()
    urlhaus_urls = fetch_urlhaus_online()
    phishtank_urls = fetch_phishtank()

    combined = openphish_urls + urlhaus_urls + phishtank_urls
    unique_urls = list(set(combined))
    print(f"Aggregated {len(unique_urls)} unique URLs from all feeds")
    return unique_urls


def update_json_file(new_urls: list, filename: str = "bad_urls.json") -> None:
    """
    Updates the JSON file by merging new URLs with existing ones, removing duplicates,
    and saving the updated list along with a timestamp and count.

    :param new_urls: The list of new phishing URLs.
    :type new_urls: list
    :param filename: The JSON filename to update.
    :type filename: str
    :return: None
    :rtype: None
    """
    # Vérifier si le fichier existe déjà
    if os.path.exists(filename):
        try:
            with open(filename, "r", encoding="utf-8") as f:
                existing_data = json.load(f)
                existing_urls = existing_data.get("urls", [])
        except Exception as e:
            print(f"Error reading {filename}: {e}")
            existing_urls = []
    else:
        existing_urls = []

    # Fusionner les anciennes et nouvelles URLs et supprimer les doublons
    combined_urls = list(set(existing_urls + new_urls))

    updated_data = {
        "updated": datetime.utcnow().isoformat() + "Z",
        "count": len(combined_urls),
        "urls": combined_urls
    }

    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(updated_data, f, indent=4)
        print(f"Updated {filename}: now contains {len(combined_urls)} unique URLs")
    except Exception as e:
        print(f"Error saving to {filename}: {e}")


if __name__ == "__main__":
    aggregated_urls = aggregate_feeds()
    update_json_file(aggregated_urls)
