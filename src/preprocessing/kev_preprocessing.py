"""
This module is responsible for cleaning CISA's KEV Catalog, which contains the
exploited vulnerabilities that the project uses to call data from the NVD,
FIRST, and ExploitDB. The Cybersecurity and Infrastructure Security Agency
(CISA) maintains the Known Exploited Vulnerabilities (KEV) Catalog as a dynamic
list of actively exploited vulnerabilities. This dataset is a critical resource
for cybersecurity professionals, as it identifies vulnerabilities that pose
significant risks to organizations and require prioritized patching. The dataset
also includes a variety of information about the vulnerabilities, including CVE
IDs, short descriptions, vendors, products, the date the CVEs were added to KEV
data, the date of required action addressing the vulnerabilities,
the vulnerability remediation, ransomware campaign use, CWE IDs, and general
notes found in external hyperlinks. The KEV catalog is ultimately going to be
the backbone of the project's analysis, with its CVE IDs being those fed to the
various APIs (e.g. NVD, FIRST, ExploitDB) that the project relies on, and this
module is responsible for the catalog's cleaning and preprocessing.

Steps required:

1. Convert data types into proper formats ✅
2. Remove extra whitespace from both ends of strings ✅
3. Standardize column and category names and titling conventions ✅
4. Remove duplicates. ✅ (There are no duplicates)
5. Standardize null values (None, '', NaN, etc.) into pd.NA values ✅
6. Remedy typos/redundancies (as much as possible). ✅
7. Remove/impute missing values (if necessary). ✅
"""

import pandas as pd
from utils import convert_cols, standardize_nulls, save_data

COL_RENAMES = {
    'cveID': 'cve_id',
    'vendorProject': 'vendor',
    'vulnerabilityName': 'cve_name',
    'dateAdded': 'kev_date_published',
    'shortDescription': 'cve_short_desc',
    'requiredAction': 'required_action',
    'dueDate': 'due_date',
    'knownRansomwareCampaignUse': 'known_use',
    'cwes': 'cwe_id'
}

COL_TYPES = {
    'string': [
        'cve_id', 'vendor', 'product', 'cve_name',
        'cve_short_desc', 'required_action', 'notes', 'cwe_id'
    ],
    'datetime': ['kev_date_published', 'due_date'],
    'category': ['known_use']
}

def run_kev_preprocessing(
        input_file: str,
        output_file: str,
        file_format: str='parquet'
    ) -> None:
    # Load the KEV
    kev = pd.read_csv(input_file)
    # Rename columns for consistency
    kev = kev.rename(columns=COL_RENAMES)
    # Convert datatypes
    kev = convert_cols(kev, COL_TYPES)
    # Wrap CWE IDs in a list for merge compatibility
    kev['cwe_id'] = kev['cwe_id'].apply(
        lambda x: [item.strip() for item in x.split(',')] if pd.notna(x) else []
    )
    # Standardize null values
    kev = standardize_nulls(kev)
    # Save the file
    save_data(kev, output_file, file_format)

# if __name__ == '__main__':
#     run_kev_preprocessing()