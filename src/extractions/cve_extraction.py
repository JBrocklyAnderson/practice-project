'''
This module accepts and parses JSON files from a given directory, extracting
values from the data according to a custom dictionary used in a recursive search
through the keys of each file. This information is then passed into a Pandas
method to convert it into a dataframe. From there, this dataframe is saved as a
raw parquet file by default, though command line arguments defined in this
project's CLI keep the output flexible. The extracted data is not cleaned or
processed in this script—these steps occur in their own respective modules.

There is still an issue with extracting CVE and CWE descriptions based on the
conditions given in the CONDITIONAL_EXTRACTIONS dictionary. I've added debugging
print statements, tried various trains of logic, refactored conditional returns
in the deep_search function, and more, to little avail. It should be working
perfectly, but it returns nothing. I have decided to move on from here for now,
considering this information is not actually immediately necessary for the
broader analysis, but will return to it in the future if a more robust text
processing becomes advantageous to the project.

Having looked at the data, it's clear that three files contain contradictory
information about the SSVC score.

This can be run with a basic command line prompt:
    python src/main.py --extract-cve
'''
import os # For accessing system tools
import time # For time-keeping
import json # For working with JSON data
import pandas as pd # For converting processed files into dataframe format
from typing import Any, Dict, List, Union, Callable # For type checking
from mappings import CVE_EXTRACTIONS, CONDITIONAL_CVE_EXTRACTIONS
from utils import save_data # For saving the data

# Create a class to parse the CVE files
class Parser:
    def __init__(self, base_path: str):
        self.base_path = base_path
        print(f'Initialized with base_path: {self.base_path}')

    def count_files(self, ext: str='.json') -> int:
        '''
        Count the files in the directory with given extension.
        '''
        total_files = 0
        for _, _, files in os.walk(self.base_path):
            total_files += sum(1 for file in files if file.endswith(ext))
        return total_files

    def process_files(self, total_files: int) -> pd.DataFrame:
        '''
        Process all files of the specified extension—default to JSON—in the base
        path.
        '''
        all_data = []
        progress = 0
        start_time = time.time()
        # Walk across the directory
        for root, _, files in os.walk(self.base_path):
            # List comprehension that creates a list of full file paths
            json_files = [
                os.path.join(root, f) # Combines the file path with the root
                for f in files # For every file in the directory
                if f.endswith('.json') # So long as it's a JSON file
            ]
            for file_path in json_files:
                result = extract_file_data(file_path, CVE_EXTRACTIONS)
                if result:
                    for key in result: # Ensure all values are lists
                        result[key] = result[key] if isinstance(
                            result[key], list
                        ) else [result[key]]
                    all_data.append(result)

                # Update progress
                progress += 1
                log_progress(progress, total_files, start_time)

        df = pd.DataFrame(all_data, dtype=object) # Prevent type coercion
        # Explicitly set column types for saving
        for col in df.columns:
            df[col] = df[col].astype(object)

        # Convert to DataFrame
        return df

def extract_file_data(
        file_path: str,
        extraction_mapping: Dict[str, List[str]]
    ) -> Dict[str, Any]:
    ''' Extract relevant data from a single JSON file. '''
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            data = json.load(file)

        # Extract data using deep search
        extracted_data = {}
        for key, paths in extraction_mapping.items():
            # # Handle conditional extractions
            # if key in CONDITIONAL_CVE_EXTRACTIONS:
            #     condition_info = CONDITIONAL_CVE_EXTRACTIONS[key]
            #     condition = condition_info.get('condition')
            #     result = deep_search(data, condition_info['paths'], condition)
            # else:
            # Perform unconditional search for each key
            result = deep_search(data, paths)
            extracted_data[key] = result

        # If fallback is necessary (if any of the CVSS values weren't found)
        cvss_keys = ['cvss_v2', 'cvss_v3', 'cvss_v3_1', 'cvss_v4']
        if not any(extracted_data[key] for key in cvss_keys):
            cvss_version = deep_search(data, ['impact.cvss.version'])
            if cvss_version: # If generic key is found
                version_switch = {
                    '2.0': (
                        'impact.cvss.baseScore', 'impact.cvss.vectorString'
                    ),
                    '3.0': (
                        'impact.cvss.baseScore', 'impact.cvss.vectorString'
                    ),
                    '3.1': (
                        'impact.cvss.baseScore', 'impact.cvss.vectorString'
                    ),
                    '4.0': (
                        'impact.cvss.baseScore', 'impact.cvss.vectorString'
                    ),
                }
                # Get keys for the IDed version
                baseScore_key, vectorString_key = version_switch.get(
                    cvss_version, (pd.NA, pd.NA)
                )
                # If the IDed version is found
                if baseScore_key:
                    extracted_data[
                        f'cvss_v{cvss_version.replace(".", "_")}'
                    ] = deep_search(data, [baseScore_key])
                    extracted_data[
                        f'cvss_v{cvss_version.replace(".", "_")}_vector'
                    ] = deep_search(data, [vectorString_key])
        # Return the extracted data
        return extracted_data
    except Exception as e:
        print(f'Error processing {file_path}: {e}')
        return {}

def deep_search(
        data: Union[Dict, List],
        target_keys: List[str],
        condition: Callable[[Any, Dict[Any, Any]], bool] = None
    ) -> Any:
    '''
    Recursively search for a value given a list of target keys paths
        Args:
            data (Union[Dict, List]): The data to search
            target_keys (List[str]): List of potential key paths
        Returns:
            A found value, a list of found values, or None if no value is found
    '''
    results = []
    def recursive_search(
            current_data: Any,
            keys: List[str],
            full_data: Dict[Any, Any]
        ) -> bool:
        # Base case: if no more keys or current data is not a dict/list
        if not keys or not isinstance(current_data, (dict, list)):
            return None
        # Current key to search
        current_key = keys[0]
        found = False # Keep track of the success of the current key path
        # If current_data is a dictionary
        if isinstance(current_data, dict):
            # Direct key match
            if current_key in current_data:
                value = current_data[current_key]
                # If this is the last key and a condition exists
                if len(keys) == 1:
                    if isinstance(value, list):
                        results.extend(
                            item for item in value
                            if condition is None or condition(item, full_data)
                        )
                    elif condition is None or condition(value, full_data):
                        results.append(value)
                    return True # Stop searching once found
                else:
                    # Otherwise, continue searching by slicing off the first key
                    found = recursive_search(
                        current_data[current_key],
                        keys[1:],
                        full_data
                    )
            # Recursive search through nested dictionaries
            for value in current_data.values():
                found = recursive_search(value, keys, full_data) or found
        # If current_data is a list, search each item
        elif isinstance(current_data, list):
            for item in current_data:
                found = recursive_search(item, keys, full_data)
        return found
    # Try each target key path
    for key_path in target_keys:
        # Split the key path into a list of individual keys
        keys = key_path.split('.')
        if recursive_search(data, keys, data):
            break

    return results if results else [None]

def log_progress(progress: int, total_files: int, start_time: float) -> None:
    elapsed_time = time.time() - start_time
    percentage = (progress / total_files) * 100 if total_files > 0 else 0
    avg_time_per_file = elapsed_time / progress if progress > 0 else 0
    remaining_time = avg_time_per_file * (total_files - progress)
    hours, remainder = divmod(remaining_time, 3600)
    minutes, seconds = divmod(remainder, 60)

    print(
        f'\rProcessed: {progress}/{total_files} '
        f'({percentage:.2f}%) | Elapsed: {elapsed_time:.2f}s) | '
        f'Remaining: {int(hours):02d}h {int(minutes):02d}m {int(seconds):02d}s',
        end=''
    )

def run_cve_extraction(
        base_dir: str,
        output_file: str,
        file_format: str='parquet'
    ) -> None:
    ''' Run CVE data extraction '''
    # Capture invalid input
    if not os.path.isdir(base_dir):
        raise ValueError(f'Base directory does not exist: {base_dir}')

    # Initialize parser
    parser = Parser(base_dir)
    # Counting total files
    total_files = parser.count_files('.json')
    print(f'Total files to process: {total_files}')
    # Processing files and updating progress
    df = parser.process_files(total_files)
    print('\nExtraction complete!')
    # Save to Parquet file
    save_data(df, output_file, file_format)

# if __name__ == '__main__':
#     run_cve_extraction()