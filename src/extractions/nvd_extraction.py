'''
This module contains extraction logic for NIST's NVD API. It utilizes an
environment variable API key that must remain ignored by git. The API client
within this module sleeps for about 1 second between requests to ensure that
legitimate calls are correctly processed and that limited network errors occur
during extraction for otherwise valid API requests.
'''
import os
import time
import requests
import pandas as pd
from utils import save_data
from typing import List, Dict
from dotenv import load_dotenv as env

# Load environment variables
env()

# Access API key
API_KEY = os.getenv('NVD_API_KEY')

# URL parameters
BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
HEADERS = {'apiKey': API_KEY}

# Maximum batch size allowed by API
RESULTS_PER_PAGE = 2000
RATE_LIMIT = 0.6

def fetch_with_exponential_backoff(
        session,
        url: str,
        headers,
        max_attempts: int=5,
        initial_wait: int=RATE_LIMIT
    ):
    attempt = 0
    wait_time = initial_wait
    while attempt < max_attempts:
        try:
            response = session.get(url, headers=headers)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            attempt += 1
            if attempt >= max_attempts:
                print(f'Max attempts reach for URL: {url}')
                raise
            print(f'Attempt {attempt} failed for URL "{url}" with error: {e}. Retrying in {wait_time} seconds...')
            time.sleep(wait_time)
            wait_time *= 2

def fetch_cve_data() -> pd.DataFrame:
    # Create receptacle for CVE data
    cve_data = []
    # Track index
    start_index = 0
    total_results = None
    # Start a session to maintain API state
    session = requests.Session()

    while total_results is None or start_index < total_results:
        url = f'{BASE_URL}?resultsPerPage={RESULTS_PER_PAGE}&startIndex={start_index}&noRejected'
        print(url)
        # url = f'{BASE_URL}?cveId=CVE-2022-0163'

        try:
            response = fetch_with_exponential_backoff(
                session,
                url,
                headers=HEADERS,
                max_attempts=8
            )
            data = response.json()

            total_results = data.get('totalResults', 0)
            vulnerabilities = data.get('vulnerabilities', [])

            for item in vulnerabilities:
                cve = item.get('cve', {})
                cve_id = cve.get('id', None)
                metrics = cve.get('metrics', {})
                date_published = cve.get('published', pd.NaT)

                # Initialize sought-after datapoints
                cvss, cvss_version, cvss_vector = None, None, None
                # Prioritize V4 > V3.1 > V3 > V2
                if 'cvssMetricV40' in metrics:
                    cvss = metrics['cvssMetricV40'][0]['cvssData'].get('baseScore')
                    cvss_version = metrics['cvssMetricV40'][0]['cvssData'].get('version')
                    cvss_vector = metrics['cvssMetricV40'][0]['cvssData'].get('vectorString')
                elif 'cvssMetricV31' in metrics:
                    cvss = metrics['cvssMetricV31'][0]['cvssData'].get('baseScore')
                    cvss_version = metrics['cvssMetricV31'][0]['cvssData'].get('version')
                    cvss_vector = metrics['cvssMetricV31'][0]['cvssData'].get('vectorString')
                elif 'cvssMetricV30' in metrics:
                    cvss = metrics['cvssMetricV30'][0]['cvssData'].get('baseScore')
                    cvss_version = metrics['cvssMetricV30'][0]['cvssData'].get('version')
                    cvss_vector = metrics['cvssMetricV30'][0]['cvssData'].get('vectorString')
                elif 'cvssMetricV2' in metrics:
                    cvss = metrics['cvssMetricV2'][0]['cvssData'].get('baseScore')
                    cvss_version = metrics['cvssMetricV2'][0]['cvssData'].get('version')
                    cvss_vector = metrics['cvssMetricV2'][0]['cvssData'].get('vectorString')

                cve_data.append({
                    'cve_id': cve_id,
                    'date_published': date_published,
                    'cvss': cvss,
                    'cvss_version': cvss_version,
                    'cvss_vector': cvss_vector,
                })

        except requests.exceptions.RequestException as e:
            print(f'HTTP {response.status_code}')
            print(
                f'Error fetching CVEs within batch starting at index {start_index} and ending at {(start_index + RESULTS_PER_PAGE) - 1}: {e}'
            )

        start_index += RESULTS_PER_PAGE
        time.sleep(RATE_LIMIT)

    return pd.DataFrame(cve_data)

def run_nvd_extraction(output_file: str, file_format: str='parquet') -> None:
    # Build dataframe
    df = fetch_cve_data()
    # Save dataframe
    save_data(df, output_file, file_format)
