'''
This is a script dedicated to preprocessing the ICS dataset and getting it ready
to be compiled into the full dataset for analysis.
'''
import pandas as pd
import numpy as np
from utils import *

def run_ics_preprocessing(
    input_file: str,
    output_file: str,
    file_format: str='parquet'
) -> None:
    # Load data
    df = pd.read_csv(input_file)
    print('Loaded data!')


    # Curate a list of columns to drop from the dataset
    suffixes = ('Impact', 'Priv', 'Required', 'updated')
    cols_to_drop = [
        col for col in df.columns
        if col.startswith('cvss_') or col.endswith(suffixes) or col in [
            'accessVector', 'complexity'
        ]
    ]
    df.drop(columns=cols_to_drop, inplace=True)
    print('Dropped unnecessary columns!')

    # Validate CVE ID
    df['cve_id'] = df['cve_id'].apply(validate_cve_id)
    print('Validated CVE ID format!\n')

    # Rename columns
    col_names = {
        'cve_description': 'cve_desc',
        'u_sys_created': 'advisory_date',
        'u_sfp_cluster': 'sfp_id',
        'u_old_cat': 'cwe_name',
        'u_new_cat': 'new_cwe_cat',
        'u_other_cat': 'impossible_to_cat_cwes',
        'u_product_type': 'product_type'
    }
    df = df.rename(columns=col_names)
    print('Renamed columns!')

    # Remove duplicates
    df = df.drop_duplicates().reset_index(drop=True)
    print('Removed duplicates!')

    # Strip whitespace
    df = strip_whitespace_from(df)
    print('Stripped whitespace!')

    # Standardize nulls
    df = standardize_nulls(df)
    print('Loaded the EPSS data!\n')

    # Convert column types
    COL_TYPES = {
        'string': [
            col for col in df.columns
            if col not in ['advisory_date', 'product_type']
        ],
        'date': ['advisory_date'],
        'category': ['product_type'],
    }
    df = convert_cols(df, COL_TYPES)
    print('Converted columns!')

    # Save data
    save_data(df, output_file, file_format)