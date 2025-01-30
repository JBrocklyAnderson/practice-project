'''
This module contains the API client that communicates with FIRST's database to
pull out EPSS data.
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
    'string': ['cve_id'],
    'date': ['epss_date'],
    'float': ['epss', 'percentile']
}

def run_epss_preprocessing(
        input_file: str,
        output_file: str,
        file_format: str='parquet'
    ) -> None:
    '''Run EPSS data preprocessing.'''
    # Load the data
    df = pd.read_parquet(path=input_file)
    print('Loaded the EPSS data!\n')

    # Strip whitespace
    df = strip_whitespace_from(df)
    print('Stripped the whitespace!\n')

    # Validate CVE ID
    df['cve_id'] = df['cve_id'].apply(validate_cve_id)
    print('Validated CVE ID format!\n')

    # Standardize nulls
    df = standardize_nulls(df)
    print('Loaded the EPSS data!\n')

    # Drop duplicates
    df = safely_drop_duplicates(df)
    print('Dropped duplicates!\n')

    # Define datatypes
    df = convert_cols(df, COL_TYPES)
    print('Converted datatypes!\n')

    # Save preprocessed data
    save_data(df, output_file, file_format)
    print('Saved preprocessed EPSS data!\n')










# if __name__ == '__main__':
#     run_epss_preprocessing()