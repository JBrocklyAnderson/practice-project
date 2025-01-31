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
    'category': ['availability', 'cvss_severity', 'cvss_severity_src']
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
    print('Data loaded!\n')

    # Fix categories for CVSS severity if their CVSS scores are 0.0
    cves.loc[
        (cves['cvss'] == 0.0) & (cves['cvss_severity'].isna()), 'cvss_severity'
    ] = 'NONE'
    # Uppercase severity categories
    cves['cvss_severity'] = cves['cvss_severity'].str.upper()
    print('CVSS severity categories fixed!\n')

    # Left-merge CVEs into exploit data
    df = pd.merge(
        exp, cves, on='cve_id', how='left', indicator=True
    )
    print('CVEs merged!\n')

    # Prioritize the earliest date a CVE could have been published
    df['date_published'] = df[['public_date', 'kev_date_published']].min(axis=1)
    print('Earliest date taken!\n')

    # Left-merge EPSS into data
    df = pd.merge(df, epss, on='cve_id', how='left', indicator='epss_merge')
    print('EPSS data merged!\n')

    # Rename columns for clarity
    df = df.rename(columns={
        'earliest_date': 'exploitation_date'
    })
    print('Columns renamed!\n')

    # Compile cve_short_desc with cve_desc
    df['cve_desc'] = df['cve_short_desc'].fillna('') + ' ' + df['cve_desc'].fillna('')
    df['cve_desc'] = df['cve_desc'].replace(' ', pd.NA)
    print('CVE descriptions compiled!\n')

    # Strip whitespace
    df = strip_whitespace_from(df)
    print('Whitespace stripped!\n')

    # Convert datetypes
    df = convert_cols(df, COL_TYPES)
    print('Datatypes converted!\n')

    # Drop columns
    cols_to_keep = [
        'cve_id',
        'date_published',
        'exploit_count',
        'exploitation_date',
        'cvss',
        'cvss_severity',
        'epss',
        'percentile'
    ]
    cols_to_drop = [col for col in df.columns if col not in cols_to_keep]
    # cols_to_drop = [
    #     'kev', # Exists from KEV
    #     'public_date', # Taken for published date
    #     'kev_date_published', # Taken for published date
    #     'epss_date', # Same as exploitation date
    #     'notes', # Links to security bulletins, etc.
    #     '_merge', # Merge artifact
    #     'epss_merge', # Merge artifact
    #     'cve_short_desc', # Subsumed within larger description
    #     'availability_requirement', # No meaningful data
    #     'availability_requirement_src', # No meaningful data
    #     'confidentiality_requirement', # No meaningful data
    #     'confidentiality_requirement_src', # No meaningful data
    #     'integrity_requirement', # No meaningful data
    #     'integrity_requirement_src', # No meaningful data
    # ]
    df = df.drop(columns=cols_to_drop)
    print('Columns dropped!\n')

    # Save the compiled dataset
    save_data(df, output_file, file_format)
    print('Saved compiled data!\n')