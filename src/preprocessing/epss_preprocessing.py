'''
This module contains the API client that communicates with FIRST's database to
pull out EPSS data. This data was explored thoroughly to determine whether
imputing EPSS and percentile data was possible with either mean or sigmoidal
imputation, but no single observation has enough data points, and the relative
minority of observations that do contain any EPSS scores most likely rules out
the accuracy of more advanced imputation algorithms.
'''
import pandas as pd
from utils import *

COL_TYPES = {
    'string': ['cve_id'],
    'date': ['epss_date_0', 'epss_date_30', 'epss_date_60'],
    'float': [
        'epss_0', 'epss_30', 'epss_60',
        'percentile_0', 'percentile_30', 'percentile_60',
        'change_0_to_30', 'change_30_to_60', 'change_total'
    ]
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

    # Ensure floats are handled correctly by imputation
    for col in df.columns:
        if col != 'cve_id' and not pd.api.types.is_datetime64_any_dtype(df[col]):
            df[col] = pd.to_numeric(df[col])

    # Impute EPSS scores by averaging or extrapolation
    # df = impute_epss(df)
    # print('EPSS scores imputed!\n')

    # Calculate change rates
    def percent_change_between_cols(col1: pd.Series, col2: pd.Series) -> pd.Series:
        return ((col2 - col1) / col1.replace(0, pd.NA)) * 100
    df['change_0_to_30'] = percent_change_between_cols(df['epss_0'], df['epss_30'])
    df['change_30_to_60'] = percent_change_between_cols(df['epss_30'], df['epss_60'])
    df['change_total'] = percent_change_between_cols(df['epss_0'], df['epss_60'])
    print('Calculated change rates!\n')

    # Standardize nulls
    df = standardize_nulls(df)
    print('Loaded the EPSS data!\n')

    # Drop duplicates
    df = safely_drop_duplicates(df)
    print('Dropped duplicates!\n')

    # Define datatypes
    df = convert_cols(df, COL_TYPES)
    print('Converted datatypes!\n')

    # Drop duplicate date column
    df.drop(columns=['epss_date'], inplace=True)
    print('Dropped duplicate date column!\n')

    # Save preprocessed data
    save_data(df, output_file, file_format)
    print('Saved preprocessed EPSS data!\n')



# if __name__ == '__main__':
#     run_epss_preprocessing()