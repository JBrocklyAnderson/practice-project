"""
This script will clean the applicable platform data scraped from MITRE's CWE
file within the 'cwe_extraction' script.
"""

# * Check category typos (everything is fine)
# * No duplicates ✅
# * Converted datatypes
# * Standardized null values
# * Saved in the directory
# * Add CLI support for this script

import pandas as pd
from utils import (
    convert_cols,
    save_data,
    standardize_nulls,
    strip_whitespace_from
)

COL_TYPES = {
    'string': ['cwe_id'],
    'category': ['type', 'name', 'class', 'prevalence', 'source_table']
}

def run_cwe_platform_preprocessing(
        input_file: str,
        output_file: str,
        file_format: str='parquet'
    ):
    # Load the data
    df = pd.read_parquet(path=input_file)
    # Add source data
    df['source_table'] = 'related_cwe_table'
    # Define datatypes
    df = convert_cols(df, COL_TYPES)
    # Standardize nulls
    df = standardize_nulls(df)
    # Drop duplicates
    df = df.drop_duplicates()
    # Strip whitespace
    df = strip_whitespace_from(df)
    # Save preprocessed data
    save_data(df, output_file, file_format)

# if __name__ == '__main__':
#     run_cwe_platform_preprocessing()
