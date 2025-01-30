'''
This module builds the project's command-line interface, e.g. the means by which
users can interact with the various scripts in order to perform specific
operations at a modular level without running the entire codebase every time
they execute a single section of the code.
'''

import argparse
from extractions import (
    run_cve_extraction,
    run_cwe_extraction,
    run_epss_extraction,
    run_poc_extraction
)

from preprocessing import (
    run_cve_preprocessing,
    run_cwe_preprocessing,
    run_related_cwe_preprocessing,
    run_cwe_platform_preprocessing,
    run_cwe_consequence_preprocessing,
    run_cwe_detection_preprocessing,
    run_cwe_mitigation_preprocessing,
    run_epss_preprocessing,
    run_poc_preprocessing,
    run_kev_preprocessing,
)

def def_args():
    '''
    Construct command-line arguments to run the project pipeline.
    '''
    # Start the argument parser
    parser = argparse.ArgumentParser(
        description='Patch Prioritization Analysis Pipeline'
    )
    # Run the whole pipeline
    parser.add_argument(
        '--run-all', action='store_true',
        help='Run all tasks in the pipeline'
    )
    # § ========================================================================
    # § Add input/output arguments for CVE data
    # § ========================================================================
    parser.add_argument(
        '--cve-input', action='store', type=str,
        help='Path to directory of JSON files from which to extract CVE data'
    )
    parser.add_argument(
        '--cve-output', action='store', type=str,
        help='Output file path for CVE data'
    )
    parser.add_argument(
        '--cve-format', action='store', type=str, default='parquet',
        choices=['parquet', 'csv', 'xlsx'],
        help='File format to save CVE data'
    )

    # § ========================================================================
    # § Add input/output arguments for CWE data
    # § ========================================================================
    parser.add_argument(
        '--cwe-input', action='store', type=str,
        help='Path to XML file from which to extract CWE data'
    )
    parser.add_argument(
        '--cwe-output', action='store', type=str,
        help='Output file path for CWE data'
    )
    parser.add_argument(
        '--cwe-format', action='store', type=str, default='parquet',
        choices=['parquet', 'csv', 'xlsx'],
        help='File format for saving CWE data'
    )
    parser.add_argument(
        '--cwe-r-input', action='store', type=str,
        help='Path to Related CWE table data'
    )
    parser.add_argument(
        '--cwe-r-output', action='store', type=str,
        help='Output file path for Related CWE table data'
    )
    parser.add_argument(
        '--cwe-p-input', action='store', type=str,
        help='Path to CWE Platform table data'
    )
    parser.add_argument(
        '--cwe-p-output', action='store', type=str,
        help='Output file path for CWE Platform table data'
    )
    parser.add_argument(
        '--cwe-c-input', action='store', type=str,
        help='Path to CWE Consequence table data'
    )
    parser.add_argument(
        '--cwe-c-output', action='store', type=str,
        help='Output file path for CWE Consequence table data'
    )
    parser.add_argument(
        '--cwe-d-input', action='store', type=str,
        help='Path to CWE Detection table data'
    )
    parser.add_argument(
        '--cwe-d-output', action='store', type=str,
        help='Output file path for CWE Detection table data'
    )
    parser.add_argument(
        '--cwe-m-input', action='store', type=str,
        help='Path to CWE Mitigation table data'
    )
    parser.add_argument(
        '--cwe-m-output', action='store', type=str,
        help='Output file path for CWE Mitigation table data'
    )

    # § ========================================================================
    # § Add input/output arguments for EPSS data
    # § ========================================================================
    parser.add_argument(
        '--epss-input', action='store', type=str,
        help='Input file path to CVEs that have PoC exploit code dates.'
    )
    parser.add_argument(
        '--epss-output', action='store', type=str,
        help='Output file path for EPSS data'
    )
    parser.add_argument(
        '--epss-format', action='store', type=str, default='parquet',
        choices=['parquet', 'csv', 'xlsx'],
        help='File format for saving EPSS data'
    )

    # § ========================================================================
    # § Add input/output arguments for PoC-GitHub data
    # § ========================================================================
    parser.add_argument(
        '--poc-input', action='store', type=str,
        help='Path to directory of JSON files from which to extract CVE data'
    )
    parser.add_argument(
        '--poc-output', action='store', type=str,
        help='Output file path for CVE data'
    )
    parser.add_argument(
        '--poc-format', action='store', type=str, default='parquet',
        choices=['parquet', 'csv', 'xlsx'],
        help='File format to save CVE data'
    )

    # § ========================================================================
    # § Add input/output arguments for KEV
    # § ========================================================================
    parser.add_argument(
        '--kev-input', action='store', type=str, help='Path to KEV catalog'
    )
    parser.add_argument(
        '--kev-output', action='store', type=str,
        help='Output file path for KEV data'
    )
    parser.add_argument(
        '--kev-format', action='store', type=str, default='parquet',
        choices=['parquet', 'csv', 'xlsx'],
        help='File format for saving KEV data'
    )

    # § ========================================================================
    # § Extraction operations
    # § ========================================================================
    parser.add_argument(
        '--extract-cve', action='store_true',
        help='Extract CVE data from MITRE database'
    )
    parser.add_argument(
        '--test-cve', action='store_true',
        help='Test CVE extraction with smaller directory'
    )
    parser.add_argument( # Also extracts CWE platform data
        '--extract-cwe', action='store_true',
        help='Extract CWE data from XML'
    )
    parser.add_argument(
        '--extract-epss', action='store_true',
        help='Extract data from the FIRST API'
    )
    parser.add_argument(
        '--extract-poc', action='store_true',
        help='Extract data from the KEV catalog'
    )

    # § ========================================================================
    # § Preprocessing operations
    # § ========================================================================
    parser.add_argument(
        '--preprocess-cve', action='store_true',
        help='Clean and preprocess extracted CVE data'
    )
    parser.add_argument(
        '--preprocess-cwe', action='store_true',
        help='Clean and preprocess extracted CWE data'
    )
    parser.add_argument( # Data comes from CWE extraction
        '--preprocess-related-cwe', action='store_true',
        help='Clean and preprocess related CWE data'
    )
    parser.add_argument( # Data comes from CWE extraction
        '--preprocess-cwe-platform', action='store_true',
        help='Clean and preprocess extracted CWE platform data'
    )
    parser.add_argument( # Data comes from CWE preprocessing
        '--preprocess-cwe-consequence', action='store_true',
        help='Clean and preprocess extracted CWE consequence data'
    )
    parser.add_argument( # Data comes from CWE preprocessing
        '--preprocess-cwe-detection', action='store_true',
        help='Clean and preprocess extracted CWE detection data'
    )
    parser.add_argument( # Data comes from CWE preprocessing
        '--preprocess-cwe-mitigation', action='store_true',
        help='Clean and preprocess extracted CWE mitigation data'
    )
    parser.add_argument(
        '--preprocess-epss', action='store_true',
        help='Clean and preprocess extracted EPSS data'
    )
    parser.add_argument(
        '--preprocess-poc', action='store_true',
        help='Clean and preprocess extracted PoC-in-GitHub data'
    )
    parser.add_argument(
        '--preprocess-kev', action='store_true',
        help='Clean and preprocess KEV dataset'
    )

    return parser.parse_args()

def run_tasks(args):
    '''
    Handle arguments given through the command line.
    '''
    # Handle all tasks
    if args.run_all:
        print('Running all tasks...\n')
        # Run CVE extration
        input_file = args.cve_input or 'data/raw/mitre/cve/cvelistV5/cves'
        output_file = args.cve_output or 'data/intermediate/mitre/cve/cve_extracted.csv'
        file_format = args.cve_format or 'parquet'
        print('Running CVE extraction...\n')
        run_cve_extraction(input_file, output_file, file_format)
        # Run CWE extraction
        input_file = args.cwe_input or '../data/raw/mitre/cwe/cwe_v4_15.xml'
        output_file = args.cwe_output or '../data/intermediate/mitre/cwe/cwe_extracted.parquet'
        file_format = args.cwe_format
        print('Running CWE extraction...\n')
        run_cwe_extraction(input_file, output_file, file_format)

        # Run NVD Extraction
        # Run EPSS Extraction
        # Run CVE Cleanup
        # Run CWE Cleanup
        # Run EPSS Cleanup
        # Run data marge

    # § ========================================================================
    # § Handle extractions
    # § ========================================================================
    if args.extract_cve:
        file_format = args.cve_format or 'parquet'
        input_dir = args.cve_input or 'data/raw/mitre/cve/cvelistV5/cves'
        output_file = args.cve_output or f'data/intermediate/mitre/cve/cve_extracted.{file_format}'
        print('Running CVE extraction...\n')
        run_cve_extraction(input_dir, output_file, file_format)

    if args.test_cve:
        file_format = args.cve_format or 'parquet'
        input_dir = args.cve_input or 'data/raw/mitre/cve/cvelistV5/cves/2024/1xxx'
        output_file = args.cve_output or f'data/intermediate/mitre/cve/cve_test.{file_format}'
        print(f'Running test CVE extraction from {input_dir}...\n')
        run_cve_extraction(input_dir, output_file, file_format)

    if args.extract_cwe: # Also produces CWE platform data
        file_format = args.cwe_format or 'parquet'
        input_file = args.cwe_input or 'data/raw/mitre/cwe/cwe_v4_15.xml'
        output_file = args.cwe_output or f'data/intermediate/mitre/cwe/cwe_extracted.{file_format}'
        print('Running CWE extraction...\n')
        run_cwe_extraction(input_file, output_file, file_format)

    if args.extract_epss:
        file_format = args.epss_format or 'parquet'
        input_file = args.epss_input or 'data/processed/composite/exploits_cleaned.parquet'
        output_file = args.epss_output or f'data/intermediate/first/epss_extracted.{file_format}'
        print('Running EPSS extraction...\n')
        run_epss_extraction(input_file, output_file, file_format)

    if args.extract_poc:
        file_format = args.poc_format or 'parquet'
        input_dir = args.poc_input or 'data/raw/exploits/poc/PoC-in-GitHub'
        output_file = args.poc_output or f'data/intermediate/exploits/poc/poc_extracted.{file_format}'
        print('Extracting proof-of-concept data from GitHub...\n')
        run_poc_extraction(input_dir, output_file, file_format)

    # § ========================================================================
    # § Handle preprocessing
    # § ========================================================================
    if args.preprocess_cve:
        file_format = args.cve_format or 'parquet'
        input_file = args.cve_input or 'data/intermediate/mitre/cve/cve_extracted.parquet'
        output_file = args.cve_output or f'data/processed/mitre/cve/cve_cleaned.{file_format}'
        print('Preprocessing CVEs...\n')
        run_cve_preprocessing(input_file, output_file, file_format)

    # Also produces CWE consequence, detection, and mitigation data
    if args.preprocess_cwe:
        file_format = args.cwe_format or 'parquet'
        input_file = args.cwe_input or f'data/intermediate/mitre/cwe/cwe_extracted.parquet'
        output_file = args.cwe_output or f'data/processed/mitre/cwe/cwe_cleaned.{file_format}'
        print('Preprocessing CWEs...\n')
        run_cwe_preprocessing(input_file, output_file, file_format)

    if args.preprocess_related_cwe:
        file_format = args.cwe_format or 'parquet'
        input_file = args.cwe_r_input or f'data/intermediate/mitre/cwe/related_cwe_extracted.parquet'
        output_file = args.cwe_r_output or f'data/processed/mitre/cwe/related_cwe_cleaned.{file_format}'
        print('Preprocessing related CWEs...\n')
        run_related_cwe_preprocessing(input_file, output_file, file_format)

    if args.preprocess_cwe_platform:
        file_format = args.cwe_format or 'parquet'
        input_file = args.cwe_p_input or f'data/intermediate/mitre/cwe/cwe_platform_extracted.parquet'
        output_file = args.cwe_p_output or f'data/processed/mitre/cwe/cwe_platform_cleaned.{file_format}'
        print('Preprocessing CWEs...\n')
        run_cwe_platform_preprocessing(input_file, output_file, file_format)

    if args.preprocess_cwe_consequence:
        file_format = args.cwe_format or 'parquet'
        input_file = args.cwe_c_input or f'data/intermediate/mitre/cwe/cwe_consequence_extracted.parquet'
        output_file = args.cwe_c_output or f'data/processed/mitre/cwe/cwe_consequence_cleaned.{file_format}'
        print('Preprocessing CWEs...\n')
        run_cwe_consequence_preprocessing(input_file, output_file, file_format)

    if args.preprocess_cwe_detection:
        file_format = args.cwe_format or 'parquet'
        input_file = args.cwe_d_input or f'data/intermediate/mitre/cwe/cwe_detection_extracted.parquet'
        output_file = args.cwe_d_output or f'data/processed/mitre/cwe/cwe_detection_cleaned.{file_format}'
        print('Preprocessing CWEs...\n')
        run_cwe_detection_preprocessing(input_file, output_file, file_format)

    if args.preprocess_cwe_mitigation:
        file_format = args.cwe_format or 'parquet'
        input_file = args.cwe_m_input or f'data/intermediate/mitre/cwe/cwe_mitigation_extracted.parquet'
        output_file = args.cwe_m_output or f'data/processed/mitre/cwe/cwe_mitigation_cleaned.{file_format}'
        print('Preprocessing CWEs...\n')
        run_cwe_mitigation_preprocessing(input_file, output_file, file_format)

    if args.preprocess_epss:
        file_format = args.cwe_format or 'parquet'
        input_file = args.epss_input or 'data/intermediate/first/epss_extracted.parquet'
        output_file = args.cwe_output or f'data/processed/mitre/cwe/cwe_cleaned.{file_format}'
        print('Preprocessing EPSS data...\n')
        run_epss_preprocessing(input_file, output_file, file_format)

    if args.preprocess_poc:
        file_format = args.poc_format or 'parquet'
        input_file = args.poc_input or 'data/intermediate/exploits/poc/poc_extracted.parquet'
        output_file = args.poc_output or f'data/processed/exploits/poc/poc_cleaned.{file_format}'
        print("Preprocessing GitHub's proof-of-concept data...\n")
        run_poc_preprocessing(input_file, output_file, file_format)

    if args.preprocess_kev:
        file_format = args.kev_format or 'parquet'
        input_file = args.kev_input or 'data/raw/cisa/kev/kev.csv'
        output_file = args.kev_output or f'data/processed/cisa/kev/kev_processed.{file_format}'
        print('Preprocessing KEV catalog...\n')
        run_kev_preprocessing(input_file, output_file, file_format)