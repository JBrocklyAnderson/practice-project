'''
This module is responsible for merging together all of the various extracted and
preprocessed parquet files gathered from the project's database and API sources.
The resulting merged dataset will be ready for further analysis.

This compilation makes sure that CVEs' CVSS severity categories are
typographically synchronized with other categorical variables and that CVEs with
CVSS scores of 0.0 have CVSS severity values of NONE instead of null, something
that can be remedied in the CVE preprocessing module at a future date. EDA in a
separate notebook confirmed that MITRE data contains neither 308 CVEs that the
composite exploit data from CISA, ExploitDB, and GitHub do contain nor any
additional CVEs that belong to CISA's KEV catalogue, so the 'kev' column is
dropped from the dataset. Another key feature of this script is that the
earliest publishing date of a CVE between the MITRE project and KEV catalogue is
preferred in the 'date_published' column. The 'earliest_date' column is changed
into 'exploitation_date' for added clarity.

Data to merge:
# TODO: Backbone — exploits_cleaned.parquet (GitHub, XDB, and KEV)
# TODO: Left merge CVE
# TODO: Left merge EPSS
# TODO: Reorder columns
# TODO: Final cleanup
'''
import pandas as pd
from utils import *

COL_TYPES = {
    'float': ['days_to_poc_exploit'],
    'category': [
        'cvss_src',
        'availability',
        'cvss_severity',
        'cvss_severity_src'
    ]
}

def run_data_compilation(
        output_file: str,
        file_format: str='parquet'
    ) -> None:
    # Load requisite data files
    exp = pd.read_parquet(
        path='data/processed/composite/exploits_cleaned.parquet'
    )
    cves = pd.read_parquet(path='data/processed/mitre/cve/cve_cleaned.parquet')
    epss = pd.read_parquet(
        path='data/processed/first/epss_cleaned.parquet'
    )
    nvd = pd.read_parquet(path='data/processed/nvd/nvd_cleaned.parquet')
    print('Data loaded!\n')

    # Left-merge CVEs into exploit data
    df = pd.merge(exp, cves, on='cve_id', how='left', indicator=True)
    print('CVEs merged!\n')

    # Left-merge EPSS into data
    # * epss_date_0 *is* the exploitation_date
    df = pd.merge(df, epss, on='cve_id', how='left', indicator='epss_merge')
    print('EPSS data merged!\n')

    # Left-merge CVSS scores from NVD
    df = pd.merge(df, nvd, on='cve_id', how='left', indicator='nvd_merge')
    print('NVD data merged!\n')

    # Prioritize the earliest date a CVE could have been published
    # ! date_public not to be confused with earliest_date !
    df['date_public'] = df[[
        'public_date',
        'date_published',
    ]].min(axis=1)
    print('Earliest date taken!\n')

    # Rename columns for clarity
    df = df.rename(columns={
        'earliest_date': 'exploitation_date_0',
        'epss_date_30': 'exploitation_date_30',
        'epss_date_60': 'exploitation_date_60',
        'change_total': 'change_0_60'
    })
    print('Columns renamed!\n')

    # Compile cve_short_desc with cve_desc
    # df['cve_desc'] = df['cve_short_desc'].fillna('') + ' ' + df['cve_desc'].fillna('')
    # df['cve_desc'] = df['cve_desc'].replace(' ', pd.NA)
    # print('CVE descriptions compiled!\n')

    # Strip whitespace
    df = strip_whitespace_from(df)
    print('Whitespace stripped!\n')

    # Calculate number of days between public date and PoC exploit publish date
    df['days_to_poc_exploit'] = df['exploitation_date_0'] - df['date_public']
    df['days_to_poc_exploit'] = df['days_to_poc_exploit'].dt.days

    # Prioritize the latest CVSS version where possible
    df['cvss_vector'] = (
        df['cvss_v4_vector']
        .combine_first(df['cvss_v3_vector'])
        .combine_first(df['cvss_v2_vector'])
        .combine_first(df['cvss_vector'])
    )
    print('CVSS vectors compiled!\n')

    # Compile CVSS scores, prioritizing those that came from CVE preprocessing
    df['cvss'] = df['cvss_x'].combine_first(df['cvss_y'])
    print('CVSS scores compiled!\n')

    # Fix categories for CVSS severity if their CVSS scores are 0.0
    cves.loc[
        (cves['cvss'] == 0.0) & (cves['cvss_severity'].isna()), 'cvss_severity'
    ] = 'NONE'

    # Uppercase severity categories
    cves['cvss_severity'] = cves['cvss_severity'].str.upper()
    print('CVSS severity categories fixed!\n')

    # Compile CVSS versions, prioritizing those that came from CVE preprocessing
    df['cvss_src'] = df['cvss_src_x'].combine_first(df['cvss_src_y'])
    print('CVSS versions compiled!\n')

    # Recalculate CVSS severity levels
    df['cvss_severity'] = df['cvss'].apply(calc_cvss_severity)
    print('CVSS severity levels recalculated!\n')

    # Recalibrate EPSS dates
    df['exploitation_date_30'] = df['exploitation_date_0'] + pd.to_timedelta(
        30, unit='D'
    )
    df['exploitation_date_60'] = df['exploitation_date_0'] + pd.to_timedelta(
        60, unit='D'
    )
    print('EPSS dates recalibrated!')

    # Convert datetypes
    df = convert_cols(df, COL_TYPES)
    print('Datatypes converted!\n')

    # Drop columns
    cols_to_keep = [
        'cve_id',
        'date_public',
        'exploit_count',
        'exploitation_date_0',
        'exploitation_date_30',
        'exploitation_date_60',
        'origin',
        'cvss',
        'cvss_src',
        'cvss_severity',
        'epss_0',
        'epss_30',
        'epss_60',
        'percentile_0',
        'percentile_30',
        'percentile_60',
        'change_0_to_30',
        'change_30_to_60',
        'change_0_60',
        'days_to_poc_exploit'
    ]
    cols_to_drop = [col for col in df.columns if col not in cols_to_keep]
    # cols_to_drop = [
    #     'kev', # Captured in origin attribute
    #     'public_date', # Captured in date_public
    #     'date_published', # Captured in published date
    #     'epss_date_0', # Captured in exploitation_date
    #     'cvss_v2_vector', # Captured in cvss_vector
    #     'cvss_v3_vector', # Captured in cvss_vector
    #     'cvss_v4_vector', # Captured in cvss_vector
    #     '_merge', # Merge artifact
    #     'epss_merge', # Merge artifact
    #     'nvd_merge', # Merge artifact
    #     'availability_requirement', # No meaningful data
    #     'availability_requirement_src', # No meaningful data
    #     'confidentiality_requirement', # No meaningful data
    #     'confidentiality_requirement_src', # No meaningful data
    #     'integrity_requirement', # No meaningful data
    #     'integrity_requirement_src', # No meaningful data
    # ]
    df = df.drop(columns=cols_to_drop)
    print('Columns dropped!\n')

    # Reorganize columns
    ordered_cols = [
        'cve_id', 'date_public', 'origin',
        'cvss', 'cvss_severity', 'cvss_src',
        'exploit_count', 'days_to_poc_exploit',
        'exploitation_date_0', 'epss_0', 'percentile_0',
        'exploitation_date_30', 'epss_30', 'percentile_30',
        'exploitation_date_60', 'epss_60', 'percentile_60',
        'change_0_to_30', 'change_30_to_60', 'change_0_60',
    ]
    # remainder_cols = [
    #     col for col in df.columns
    #     if col not in ordered_cols and col != 'cvss_vector'
    # ]
    # ordered_cols = ordered_cols + ['cvss_vector'] + remainder_cols
    df = df[ordered_cols]
    print('Columns reordered!\n')

    # Save the compiled dataset
    save_data(df, output_file, file_format)
    print('Saved compiled data!\n')