'''
This module is responsible for extracting EPSS scores from the API exposed by
FIRST. The filtering that takes place (e.g. removing CVEs whose exploit code
publish dates occur prior to when EPSS scores began being calculated) accounts
for the discrepancy between the number of non-null values in 'epss_date_0' and
'exploitation_date' while working through the project's data_compilation script.
'''
import pandas as pd # For transforming gathered data
import requests # For establishing contact with API
import time # For sleeping API requests to respect rate limits
from datetime import datetime, timedelta
from typing import List, Tuple, Dict, Any # For type checking
from utils import save_data # For saving the data

def extract_epss(
        cves: List[str],
        dates: List[datetime],
        base_url: str,
        headers: Dict[str, str]
    ) -> Tuple[pd.DataFrame, pd.DataFrame]:
    '''
    Extract EPSS scores from FIRST API for given CVE IDs and dates.
    Args:
        cve_ids (List[str]): List of CVE IDs.
        earliest_dates (List[datetime]): Corresponding earliest dates for each CVE ID.
        base_url (str): Base URL of the FIRST API endpoint.
    Returns:
        Tuple[pd.DataFrame, pd.DataFrame]:
            - A dataframe containing CVE IDs and their EPSS scores.
            - A list of dictionaries recording missing EPSS score combinations.
    '''
    epss_data = []
    missing_data = []
    rate_limit = 1000 # Calls per minute
    pause_duration = 60 / rate_limit # Pause in seconds between calls
    date_offsets = [0, 30, 60]

    for cve, date in zip(cves, dates):
        epss_entry = {'cve_id': cve, 'epss_date': date}

        for offset in date_offsets:
            # Take the date before the CVE's first PoC exploit code was published
            query_date = (date + timedelta(days=offset))
            # Capture query date
            epss_entry[f'epss_date_{offset}'] = query_date
            # Format date for API call
            query_date = query_date.strftime('%Y-%m-%d')
            # Store query date for this offset
            url = f'{base_url}?cve={cve}&date={query_date}&pretty=true'
            print(f'Called with URL : {url}')

            try:
                # Call the API
                response = requests.get(url, headers=headers)
                response.raise_for_status()
                metadata = response.json()

                if 'data' in metadata and metadata['data']:
                    epss_entry[f'epss_{offset}'] = metadata['data'][0].get('epss')
                    epss_entry[f'percentile_{offset}'] = metadata['data'][0].get('percentile')
                else: # Record CVEs with missing scores for the given query date
                    missing_data.append({
                        'cve_id': cve,
                        'date': query_date,
                        'reason': 'No records available.'
                    })
            except requests.exceptions.RequestException as e:
                missing_data.append({'cve_id': cve, 'date': query_date, 'reason': str(e)})
            # Respect rate limit
            time.sleep(pause_duration)

        epss_data.append(epss_entry)

    epss_df = pd.DataFrame(epss_data)
    missing_df = pd.DataFrame(missing_data)
    return epss_df, missing_df

def run_epss_extraction(
        input_file: str,
        output_file: str,
        file_format: str='parquet'
    ) -> None:
    '''
    Run EPSS data extraction.
    Args:
        input_file (str): Path to a DataFrame containing a 'cve_id' column.
        output_file (str): The output file path.
        file_format (str): The desired file format. Default is 'parquet'.
    '''
    # Load the CVEs
    input_data = pd.read_parquet(path=input_file)
    input_data = input_data.dropna(subset=['earliest_date'])

    # Filter out CVE's whose proof-of-concept exploit date occurs prior to when
    #   EPSS started being calculated
    input_data = input_data[
        input_data['earliest_date'] >= pd.Timestamp(
            datetime(2021, 4, 14), tz='UTC'
        )
    ]
    cves = input_data['cve_id'].tolist()
    dates = pd.to_datetime(input_data['earliest_date']).tolist()

    # # TEST: Limit number of CVEs
    # cves = cves[:5]
    # dates = dates[:5]

    base_url = 'https://api.first.org/data/v1/epss'
    headers = {'Accept': 'application/json'}

    df, missing = extract_epss(cves, dates, base_url, headers)

    # Save the data
    save_data(df, output_file, file_format)

    if not missing.empty:
        print(
            f'Found {len(missing)} missing EPSS scores. Saving to "data/intermediate/first/missing_epss_scores"'
        )
        save_data(
            missing,
            f'data/intermediate/first/missing_epss_scores.{file_format}',
            file_format
        )
    print(f'EPSS scores saved to {output_file}')

# if __name__ == '__main__':
#     run_epss_extraction()