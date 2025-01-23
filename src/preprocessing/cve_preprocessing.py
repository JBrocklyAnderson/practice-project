'''
This module contains the configuration of utility functions and specialty steps
required for cleaning the CVE data pulled from MITRE's JSON-based CVE database.

Steps required:

# * Drop the first two rows (they came from metadata files and are not themselves
    CVE records)
# * Flatten single-item listed attributes
# * Extract the first index of certain columns
# * Convert data types into proper formats
# * Remove extra whitespace from both ends of strings
# * Standardize column and category names and titling conventions
# * Check for typos/redundancies in categorical data.
# * Remove duplicates
# * Standardize null values (None, '', NaN, etc.) into pd.NA values.
# * Drop extraneous columns.
# * Compute CVSS score categories
# * Extract features from CVSS vectors
# * Compile CVSS score columns and flag their origins
# * Discover and correct the index misalignment that occurs when dropping
# *     rejected CVEs
'''

import pandas as pd
import numpy as np
from mappings import CVSS_COL_MAP
from utils import (
    compile_cols,
    concat_col,
    convert_cols,
    extract_cvss_metrics,
    extract_cvss_severity,
    extract_max_cvss_score_and_vector,
    flatten_cols,
    save_data,
    safely_drop_duplicates,
    standardize_categories,
    standardize_nulls,
    validate_cve_id
)

COL_TYPES = {
    'string': [
        'cve_id',
        'cve_desc',
        'solution',
        'cvss_v2_vector',
        'cvss_v3_vector',
        'cvss_v4_vector'
    ],
    'float': ['cvss'],
    'datetime': [
        'mitre_cve_res_date',
        'public_date'
    ],
    'category': [
        'cve_discovery',
        'cvss_src',
        'cvss_v2_cat',
        'cvss_v3_cat',
        'cvss_v4_cat',
        'cvss_v2_severity',
        'cvss_v3_severity',
        'cvss_v4_severity',
        'attack_vector',
        'attack_vector_src',
        'attack_complexity',
        'attack_complexity_src',
        'privileges_required',
        'privileges_required_src',
        'scope',
        'scope_src',
        'confidentiality',
        'confidentiality_src',
        'integrity',
        'integrity_src',
        'availability_src',
        'exploit_maturity',
        'exploit_maturity_src',
        'remediation_level',
        'remediation_level_src',
        'report_confidence',
        'report_confidence_src',
        'confidentiality_requirement',
        'confidentiality_requirement_src',
        'integrity_requirement',
        'integrity_requirement_src',
        'availability_requirement',
        'availability_requirement_src',
        'authentication',
        'authentication_src',
        'collateral_damage_potential',
        'collateral_damage_potential_src',
        'target_distribution',
        'target_distribution_src',
        'attack_requirements',
        'attack_requirements_src',
        'sub_sys_confidentiality',
        'sub_sys_confidentiality_src',
        'sub_sys_integrity',
        'sub_sys_integrity_src',
        'sub_sys_availability',
        'sub_sys_availability_src',
        'ssvc_exploitation',
        'ssvc_exploitation_src',
        'ssvc_automatable',
        'ssvc_automatable_src',
        'ssvc_tech_impact',
        'ssvc_tech_impact_src',
        'recovery',
        'recovery_src',
        'response_effort',
        'response_effort_src',
        'safety',
        'safety_src',
        'automatable',
        'automatable_src',
        'urgency',
        'urgency_src',
        'value_density',
        'value_density_src',
        'user_interaction',
        'user_interaction_src'
    ],
    'boolean': ['kev']
}

CATEGORY_MAP = {
    'cve_discovery': {
        'external': 'EXTERNAL',
        'internal': 'INTERNAL',
        'discovery statement': 'Discovery Statement'
    },
    'ssvc_exploitation': {
        'none': 'NONE',
        'poc': 'POC',
        'PoC': 'POC',
        'active': 'ACTIVE',
        'Active': 'ACTIVE'
    },
    'ssvc_automatable': {
        'no': 'NO',
        'No': 'NO',
        'yes': 'YES',
        'Yes': 'YES'
    },
    'ssvc_tech_impact': {
        'partial': 'PARTIAL',
        'Partial': 'PARTIAL',
        'total': 'TOTAL',
        'Total': 'TOTAL',
    },
    'cvss_v2_severity': {
        'Low': 'LOW',
        'Medium': 'MEDIUM',
        'High': 'HIGH',
    },
    'cvss_v3_severity': {
        'None': 'NONE',
        'Low': 'LOW',
        'Medium': 'MEDIUM',
        'High': 'HIGH',
        'Critical': 'CRITICAL',
    },
    'cvss_v4_severity': {
        'None': 'NONE',
        'Low': 'LOW',
        'Medium': 'MEDIUM',
        'High': 'HIGH',
        'Critical': 'CRITICAL',
    }
}

def run_cve_preprocessing(
        input_file: str,
        output_file: str,
        file_format: str='parquet'
    ):
    # Load the CVE file
    df = pd.read_parquet(path=input_file)
    print('Loaded the CVE data!')

    # Drop the first two empty rows
    df = df.drop(index=[0, 1])
    # Reset the index
    df = df.reset_index(drop=True)
    print('Dropped first two rows!\n')

    # Pull out CVSS targets from incongruous CVSS observations
    df = extract_max_cvss_score_and_vector(df, 'cvss_v3_1', 'cvss_v3_1_vector')
    print('Max scores attained from lists in CVSS V3.1!')
    df = extract_max_cvss_score_and_vector(df, 'cvss_v4', 'cvss_v4_vector')
    print('Max scores attained from lists in CVSS V4!')

    # Extract the first item for columns with duplicates
    cols_w_duplicates = [
        'cve_id', 'cve_desc', 'cve_state', 'cve_discovery',
        'ssvc_exploitation', 'ssvc_automatable', 'ssvc_tech_impact'
    ]
    for col in cols_w_duplicates:
        df[col] = df[col].apply(
            lambda x: x[0]
            if isinstance(x, (list, np.ndarray)) and len(x) > 0 else pd.NA
        )
        print(f'''The first item in "{col}"'s lists has been grabbed.''')

    # Flatten columns containing single-item lists (if any)
    df = flatten_cols(df, df.columns)
    print('Flattened columns containing single-item lists!\n')

    # Shave off rejected CVEs
    df = df[df['cve_state'] == 'PUBLISHED'].reset_index(drop=True)
    print('Dropped rejected vulnerabilities!')

    # Handle CWE descriptions
    def extract_cwe_desc(desc_list):
        if not isinstance(desc_list, (list, np.ndarray)):
            print(f'Skipping non-list or non-array value: {type(desc_list)}')
            return []  # Return an empty list for invalid data types
        return [
            cwe.get('description', '') for cwe in desc_list
            if isinstance(cwe, dict)
            and cwe.get('lang', '').lower() in ['en', 'eng', 'english']
        ]
    df['cwe_desc'] = df['cwe_desc'].apply(extract_cwe_desc)
    print('Extracted English CWE descriptions!\n')

    # Combine CVSS V3 and V3.1, prioritizing V3.1
    df['cvss_v3'] = df['cvss_v3_1'].combine_first(df['cvss_v3'])
    df['cvss_v3_vector'] = df['cvss_v3_1_vector'].combine_first(
        df['cvss_v3_vector']
    )
    print('Combined CVSS V3 and V3.1!\n')

    # Extract CVSS severity features
    cvss_cols = ['cvss_v2', 'cvss_v3', 'cvss_v4']
    df = extract_cvss_severity(df, cvss_cols)
    print('Severity levels calculated from CVSS scores')

    # Take stock of columns to drop (the state of all CVEs is now published)
    cols_to_drop = [
        'cve_state',
        'cwe_desc',
        'mitre_cve_publish_date',
        'mitre_cve_public_date',
        'cvss_v3_1',
        'cvss_v3_1_vector',
        'is_kev'
    ]

    # Draft subtables
    save_path = 'data/intermediate/mitre/cve/'
    TABLE_CONFIG = {
        'cve-cwe connection': {
            'cols': ['cwe_id', 'cwe_desc'],
            'output_file': f'{save_path}cve_cwe_connection.{file_format}'
        },
        'cve product table': {
            'cols': [
                'vendor',
                'product',
                'prod_status',
                'prod_defaultStatus',
                'prod_version',
                'prod_version_type',
                'prod_lessThan',
                'prod_lessThanOrEqual',
                'cpe'
            ],
            'output_file': f'{save_path}cve_product.{file_format}'
        }
    }
    for table, config in TABLE_CONFIG.items():
        # Extract the subtable
        sub_df = df[['cve_id'] + config['cols']].copy()
        print(f'"{table}" has been found.')

        save_data(
            sub_df,
            config['output_file'],
            file_format
        )
        print(f'"{table}" has been successfully saved.')
        # Add extracted columns to drop list
        cols_to_drop.extend(config['cols'])

    # Concatenate items within the solution column
    cols_to_concat = ['solution']
    df = concat_col(df, cols_to_concat, ' ')
    print(f'Concatenated necessary columns!\n')

    # Check the validity of CVE IDs
    df['cve_id'] = df['cve_id'].apply(validate_cve_id)
    print('Validated CVE IDs!\n')

    # Standardize CVE discovery values
    df = standardize_categories(df, CATEGORY_MAP)
    print('Standardized DataFrame categories!\n')

    # Extract CVSS base, temporal, and environmental metrics
    for version in ['cvss_v2_vector', 'cvss_v3_vector', 'cvss_v4_vector']:
        df = extract_cvss_metrics(df, version)
        print(f'Extracted CVSS metrics for {version}!\n')

    # Compile CVSS metric versions into unified columns
    df = compile_cols(df, CVSS_COL_MAP)
    print('Columns compiled!\n')

    # Return True if 'kev'
    df['kev'] = df['is_kev'].apply(
        lambda x: 'kev' in x if isinstance(x, (list, np.ndarray)) else False
    )
    print('Flagged KEV!\n')

    # Take the earliest date of CVE appearance
    df['public_date'] = df.apply(
        lambda row: min(
            row['mitre_cve_publish_date'], row['mitre_cve_public_date']
        ) if pd.notna(row['mitre_cve_publish_date'])
        and pd.notna(row['mitre_cve_public_date'])
        else row['mitre_cve_publish_date']
        or row['mitre_cve_public_date'],
        axis=1
    )
    print('Captured earliest date!')

    # Standardize null values
    df = standardize_nulls(df)
    print('Standardized null values!\n')

    # Drop the necessary columns
    df = df.drop(columns=cols_to_drop)
    print('Dropped unnecessary columns!\n')

    # Drop duplicates
    df = safely_drop_duplicates(df)
    print('Dropped duplicates!\n')

    # Convert columns to the specified types
    df = convert_cols(df, COL_TYPES)
    print('Converted column datatypes!\n')

    # Save the preprocessed data
    save_data(df, output_file, file_format)
    print('Saved preprocessed CVE data!\n')

# if __name__ == '__main__':
#     run_cve_preprocessing()