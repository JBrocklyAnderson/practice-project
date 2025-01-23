'''
This script contains an orchestration of modular functions found in the utils
module for the purposes of cleaning and preparing the proof-of-concept exploit
metadata (PoCEM) extracted from GitHub for analysis. The program searches for CVE IDs
primarily from the 'name' field of each JSON file that houses a list of exploit
code dictionaries. If one cannot be found there, it searches through the list of
'poc_topics' if any were provided. No other fields would make sense to search.

Preliminary EDA confirmed that there are 746 proof-of-concept exploit codes that
cannot be associated with their respective specific vulnerability IDs. These are
dropped from the preprocessed dataset. 5439 CVEs with proof-of-concept exploits
remain in the dataset, the earlist of which was uploaded on 2010-09-14. Most of
these vulnerabilities have just a single PoC exploit, but some have as many as
391. The mean is 2.481 with a standard deviation of 8.271.

The GitHub PoCEM dataset is padded with PoCEM data from ExploitDB in separate
extraction and preprocessing scripts.
'''

import pandas as pd
from utils import (
    convert_cols,
    save_data,
    safely_drop_duplicates,
    standardize_nulls,
    strip_whitespace_from,
    validate_cve_id
)

COL_TYPES = {
    'string': [
        'cve_id',
    ],
    'integer': ['exploit_count', 'poc_forks'],
    'datetime': [
        'earliest_date'
    ],
    'category': [
        'poc_visibility'
    ],
}

def run_poc_preprocessing(
    input_file: str,
    output_file: str,
    file_format: str='parquet'
) -> None:
    # Load the CVE file
    df = pd.read_parquet(path=input_file)
    print('Loaded the proof-of-concept data!')

    # Validate CVE ID
    df['cve_id'] = df.apply(
        lambda row: validate_cve_id(row['cve_id'], row['poc_topics']),
        axis=1
    )

    # Drop rows where CVE ID could not be found
    df = df[df['cve_id'].notna()]
    print(f'Dropped {len(df) - len(df[df["cve_id"].notna()])} rows without CVE IDs!')

    # Standardize null values
    df = standardize_nulls(df)
    print('Standardized null values!\n')

    # Drop unnecessary columns
    cols_to_drop = [
        'poc_creation',
        'poc_uploaded',
        'poc_forks',
        'poc_topics',
        'poc_visibility'
    ]
    df = df.drop(columns=cols_to_drop)

    # Drop duplicates
    df = safely_drop_duplicates(df)
    print('Dropped duplicates!\n')

    # Remove extraneous whitespace
    df = strip_whitespace_from(df)

    # Convert columns to the specified types
    df = convert_cols(df, COL_TYPES)
    print('Converted column datatypes!\n')

    # Save the preprocessed data
    save_data(df, output_file, file_format)
    print('Saved preprocessed CVE data!\n')

