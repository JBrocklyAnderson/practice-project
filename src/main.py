"""
This script serves as the entry point and orchestrator for the project's
codebase. It includes the ressource-intensive extraction of data from hundreds
of thousands of JSON files, large XML files, and API responses, heavy
preprocessing of this data into useable files, and the merging together of all
of this data into a format better suited for robust analysis.
"""

# * CVE Extraction
# * CWE Extraction
# * CWE Platform Extraction
# TODO: EPSS Extraction
# TODO: NVD Extraction
# TODO: ExploitDB Extraction
# TODO: CVE Preprocessing
# * CWE Preprocessing
# * CWE Platform Extraction
# * CWE Consequence Extraction
# * CWE Detection Extraction
# * CWE Mitigation Extraction
# * Related CWE Extraction
# * CWE Platform Preprocessing
# * CWE Consequence Preprocessing
# * CWE Detection Preprocessing
# * CWE Mitigation Preprocessing
# * Related CWE Preprocessing
# TODO: EPSS Preprocessing
# TODO: NVD Processing
# TODO: ExploitDB Preprocessing
# * KEV Preprocessing
# TODO: Data Merge and Postprocessing


from cli import *
from utils import save_data

def main():
    args = def_args()
    run_tasks(args)

    # # Save data down here after the cleaning and merging scripts
    # save_data(final_df, input_file, output_file)

if __name__ == '__main__':
    main()