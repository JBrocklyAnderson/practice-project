"""
This script cleans and processes the CWE data scraped from MITRE's XML sheet. At
the same time, it extracts multiple subtables from that enable the project to
analyze various relationships by exploding lists without producing cartesian
duplicates.

Steps required:

- Convert data types into proper formats ✅
- Prepend 'CWE-' to IDs ✅
- Combine the description, extended description, and background details,
    making sure that the description ends with proper punctuation and everything
    is separated by a space. ✅
- Check the number of items in listed columns. If every observation's list has
    just 1 item, then flatten the list. If every observation's has has the same
    number of items, then split the lists across multiple ordinal columns. ✅
- Remove extra whitespace from both ends of strings ✅
- Flatten the items of the background details into a single string ✅
- Standardize column and category names and titling conventions
- Remove duplicates ✅
- Standardize null values (None, '', NaN, etc.) into pd.NA values ✅
- Extract sub-tables and explode them into long format after standardizing their
    list lengths ✅
"""

import pandas as pd
import numpy as np
from utils import (
    concat_col,
    convert_cols,
    extract_and_explode,
    flatten_cols,
    safely_drop_duplicates,
    save_data,
    standardize_nulls,
    strip_whitespace_from
)

COL_TYPES = {
    'string': [
        'cwe_id',
        'cwe_name',
        'cwe_exploit_likelihood'
    ]
}

def run_cwe_preprocessing(
        input_file: str,
        output_file: str,
        file_format: str='parquet'
    ) -> None:
    # Load the CWE file
    df = pd.read_parquet(path=input_file)
    # Convert datatypes
    df = convert_cols(df, COL_TYPES)
    # Prepend 'CWE-' to IDs
    df['cwe_id'] = df['cwe_id'].apply(
        lambda x: f'CWE-{x}' if pd.notna(x) else pd.NA
    )
    # Draft subtables
    save_path = 'data/intermediate/mitre/cwe/'
    TABLE_CONFIG = {
        'related cwe table': {
            'cols': ['cwe_related_id', 'cwe_nature_of_rel'],
            'output_file': f'{save_path}related_cwe_extracted.{file_format}'
        },
        'cwe consequence table': {
            'cols': [
                'cwe_consequence_scope', 'cwe_consequence_impact',
                'cwe_consequence_note'
            ],
            'output_file': f'{save_path}cwe_consequence_extracted.{file_format}'
        },
        'cwe detection table': {
            'cols': [
                'cwe_detect_method', 'cwe_detect_desc',
                'cwe_detect_effectiveness', 'cwe_detect_effect_notes'
            ],
            'output_file': f'{save_path}cwe_detection_extracted.{file_format}'
        },
        'cwe mitigation table': {
            'cols': [
                'cwe_miti_phase', 'cwe_miti_desc',
                'cwe_miti_effect', 'cwe_miti_effect_notes'
            ],
            'output_file': f'{save_path}cwe_mitigation_extracted.{file_format}'
        }
    }
    for table, config in TABLE_CONFIG.items():
        sub_df = extract_and_explode(df, 'cwe_id', config['cols'], table)
        save_data(
            sub_df,
            config['output_file'],
            file_format
        )
    # Concatenate background details
    df = concat_col(df, 'cwe_bg_details')
    # Combine description, extended description, and background details
    df['cwe_desc_combined'] = np.where(
        df['cwe_desc'].isna()
        & df['cwe_desc_extended'].isna()
        & df['cwe_bg_details'].isna(),
        pd.NA,
        (
            df['cwe_desc']
            .fillna('') + ' ' + df['cwe_desc_extended']
            .fillna('') + ' ' + df['cwe_bg_details']
        ).str.strip()
    )
    # Drop columns extracted into subtables
    cols_to_drop = [
        col for table in TABLE_CONFIG.values()
        for col in table['cols']
    ]
    cols_to_drop.extend(['cwe_desc', 'cwe_desc_extended', 'cwe_bg_details'])
    df = df.drop(columns=cols_to_drop)
    # Flatten columns containing single-item lists (if any)
    df = flatten_cols(df, df.columns)
    # Drop duplicates
    df = safely_drop_duplicates(df)
    # Strip whitespace
    df = strip_whitespace_from(df)
    # Standardize null values
    df = standardize_nulls(df)
    # Save the file
    save_data(df, output_file, file_format)

# if __name__ == '__main__':
#     run_cwe_preprocessing()