"""
This script will clean the CWE detection data pulled out of the project's main
CWE data within the 'cwe_preprocessing' script.
"""

import pandas as pd
from utils import (
    convert_cols,
    save_data,
    standardize_nulls,
    strip_whitespace_from
)

COL_TYPES = {
    'string': ['cwe_id', 'cwe_detect_desc', 'cwe_detect_effect_notes'],
    'category': [
        'cwe_detect_method', 'cwe_detect_effectiveness', 'source_table'
    ]
}

def run_cwe_detection_preprocessing(
        input_file: str,
        output_file: str,
        file_format: str='parquet'
    ):
    # Load the data
    df = pd.read_parquet(path=input_file)
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
#     run_cwe_detection_preprocessing()