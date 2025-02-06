'''
This module cleans and preprocesses the NVD data extracted from NIST. It
provides the final production dataset with additional CVSS scores and vectors.
'''
import pandas as pd
from utils import *

COL_TYPES = {
    'string': ['cve_id', 'cvss_vector'],
    'datetime': ['date_published'],
    'float': ['cvss'],
    'category': ['cvss_src']
}

def run_nvd_preprocessing(
        input_file: str,
        output_file: str,
        file_format: str='parquet'
    ) -> None:
    '''
    Run NVD data preprocessing.
    Args:
        input_file (str): The path to the NVD dataset file.
        output_file (str): The output file path.
        file_format (str): The desired file format. Default is 'parquet'.
    '''
    # Load the NVD data
    df = pd.read_parquet(path=input_file)
    print('Data loaded!\n')

    # Replace CVSS version values
    df['cvss_version'] = df['cvss_version'].replace({
        '2.0': 'V2',
        '3.0': 'V3',
        '3.1': 'V3.1',
        '4.0': 'V4',
    })
    print('CVSS version values replaced!\n')

    # Rename CVSS version attribute
    df = df.rename(columns={'cvss_version': 'cvss_src'})
    print('CVSS version attribute renamed!\n')

    # Validate CVE ID
    df['cve_id'] = df['cve_id'].apply(validate_cve_id)
    print('Validated CVE ID format!\n')

    # Strip whitespace
    df = strip_whitespace_from(df)
    print('Stripped whitespace!\n')

    # Standardize nulls
    df = standardize_nulls(df)
    print('Standardized nulls!\n')

    # Drop duplicates
    df = df.drop_duplicates()
    print('Dropped duplicates!\n')

    # Convert column types
    df = convert_cols(df, COL_TYPES)
    print('Converted column datatypes!\n')

    # Save preprocessed data
    save_data(df, output_file, file_format)
