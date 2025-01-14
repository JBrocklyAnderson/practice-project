'''
This script walks through the local clone of the PoC-in-GitHub database to
extract key values from JSON files. The code is based on the implementation of
the CVE extraction program.
'''

import os # For accessing system tools
import time # For time-keeping
import json # For working with JSON data
import pandas as pd # For converting processed files into dataframe format
from typing import Any, Dict, List, Union, Callable # For type checking
from mappings import POC_EXTRACTIONS
from utils import save_data # For saving the data

# Create a class to parse JSON files
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
        Process all JSON files in the directory to extract proof-of-concept exploit metadata.
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
                result = extract_file_data(file_path, POC_EXTRACTIONS)
                if result:
                    all_data.append(result)

                # Update progress
                progress += 1
                log_progress(progress, total_files, start_time)
        df = pd.DataFrame(all_data) # Prevent type coercion
        # Convert to DataFrame
        return df

def extract_file_data(file_path: str, extraction_mapping: Dict[str, List[str]]) -> Dict[str, Any]:
    ''' Extract relevant data from a single JSON file. '''
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            data = json.load(file)

        extracted_data = {}
        exploit_count = len(data)
        earliest_date = min((entry.get('created_at') for entry in data), default=None)

        extracted_data['exploit_count'] = exploit_count
        extracted_data['earliest_date'] = earliest_date

        for key, paths in extraction_mapping.items():
            extracted_data[key] = deep_search(data, paths)

        return extracted_data
    except Exception as e:
        print(f'Error processing {file_path}: {e}')
        return {}

def deep_search(data: Union[Dict, List], target_keys: List[str]) -> Any:
    results = []

    def recursive_search(current_data: Any, keys: List[str]) -> None:
        if not keys or not isinstance(current_data, (dict, list)):
            return
        current_key = keys[0]
        if isinstance(current_data, dict):
            if current_key in current_data:
                value = current_data[current_key]
                if len(keys) == 1:
                    results.append(value)
                else:
                    recursive_search(value, keys[1:])
            else:
                for value in current_data.values():
                    recursive_search(value, keys)
        elif isinstance(current_data, list):
            for item in current_data:
                recursive_search(item, keys)

    for key_path in target_keys:
        recursive_search(data, key_path.split('.'))

        # Flatten lists to ensure multiple matches are combined
    flattened_results = []
    for result in results:
        if isinstance(result, list):
            flattened_results.extend(result)
        else:
            flattened_results.append(result)

    # Return as-is if the original target is a list
    return (
        flattened_results if any(isinstance(data, list)
        for data in results) else results[0] if results else None
    )

    return results[0] if results else None

def log_progress(progress: int, total_files: int, start_time: float) -> None:
    elapsed_time = time.time() - start_time
    percentage = (progress / total_files) * 100 if total_files > 0 else 0
    avg_time_per_file = elapsed_time / progress if progress > 0 else 0
    remaining_time = avg_time_per_file * (total_files - progress)
    hours, remainder = divmod(remaining_time, 3600)
    minutes, seconds = divmod(remainder, 60)

    print(
        f'\rProcessed: {progress}/{total_files} '
        f'({percentage:.2f}%) | Elapsed: {elapsed_time:.2f}s | '
        f'Remaining: {int(hours):02d}h {int(minutes):02d}m {int(seconds):02d}s',
        end=''
    )

def run_poc_extraction(
        base_dir: str,
        output_file: str,
        file_format: str='parquet'
) -> None:
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
#     run_poc_extraction()