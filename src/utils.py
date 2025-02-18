'''
Common functions useful for file wrangling, data cleaning and processing, statistical analysis,
and visualization can be found in this module. These functions were created to
preserve the functionality of prior notebooks, reduce code duplication, and keep
the project readable, maintainable, and scalable.
'''

import pandas as pd
import numpy as np
import json
import re
from typing import List, Dict, Union, Tuple
from scipy.optimize import curve_fit
from mappings import (
    TOTAL_CVSS_MAPPINGS,
    CVSS_BASE_METRICS,
    CVSS_VERSION_SPECIFIC_METRIC_OVERRIDES
)

# § ============================================================================
# § File Operations
# § ============================================================================
def save_data(
        df: pd.DataFrame,
        file_path: str,
        file_format: str='parquet',
        index: str=None,
        **kwargs
    ) -> None:
    '''
    Saves a dataframe in the specified destination as a specified format
    Args:
        df (pd.DataFrame): The data to save
        file_path (str): The output file path
        file_format (str): The desired file format ('parquet', 'csv', 'excel')
        index (bool): Saved file's index preferences (default: None)
        **kwargs: Additional keyword arguments passed to Pandas save methods
    '''
    format_switch = {
        'parquet': lambda: df.to_parquet(
            path=file_path,
            index=index,
            **kwargs
        ),
        'csv': lambda: df.to_csv(file_path, index=index, **kwargs),
        'excel': lambda: df.to_excel(file_path, index=index, **kwargs),
        'xlsx': lambda: df.to_excel(file_path, index=index, **kwargs),
    }
    try:
        save_function = format_switch.get(file_format.lower())
        if not save_function:
            raise ValueError(f'Unsupported file format: {file_format}')
        save_function()
        print(f'Data successfully saved to {file_path} !')
    except Exception as e:
        print(f'Error saving data: {e}')

# § ============================================================================
# § Data Cleaning
# § ============================================================================
def safely_drop_duplicates(df: pd.DataFrame) -> pd.DataFrame:
    '''
    Duplicates can't be dropped if columns passed to the drop_duplicates
    function are not hashable datatypes. This function ensure all non-hashable
    datatypes are converted into hashable datatypes for comparison evaluation in
    the drop_duplicates function and reconverts them into their original
    datatypes after duplicates have been dropped.
    Args:
        df (pd.DataFrame): The DataFrame to process.
    Returns:
        A DataFrame with duplicates dropped.
    '''
    # Convert non-hashable columns to simple strings for comparison
    hashable_cols = id_hashable_cols(df)
    unhashable_cols = [
        col for col in df.columns
        if col not in hashable_cols
    ]
    print(f'Unhashable columns: {unhashable_cols}')
    # Store original data types for non-hashable columns

    # Convert unhashable columns to hashable formats
    for col in unhashable_cols:
        df[col] = df[col].apply(
            lambda x: 'null' if x is pd.NA
            else json.dumps(x.tolist()) if isinstance(x, np.ndarray)
            else json.dumps(x)
        )
    # Drop duplicates
    df = df.drop_duplicates().reset_index(drop=True)
    # Convert back to original data types
    for col in unhashable_cols:
        df[col] = df[col].apply(
            lambda x: np.array(json.loads(x)) if isinstance(x, str) and x != 'null' else None
        )
    return df

def standardize_categories(
        df: pd.DataFrame,
        category_mappings: Dict[str, Dict[str, str]]
    ) -> pd.DataFrame:
    '''
    Standardize the categories in specified columns based on provided mappings.
    Args:
        df (pd.DataFrame): The input DataFrame.
        category_mappings (dict): A dictionary where keys are column names and
                                values are dictionaries mapping old categories
                                to new standardized ones.
    Returns:
        pd.DataFrame: The DataFrame with standardized categories.
    '''
    for col, mapping in category_mappings.items():
        if col in df.columns:
            df[col] = df[col].apply(
                lambda cell: mapping[cell.lower()]
                if isinstance(cell, str) and cell.lower() in mapping
                else cell
            )
    return df

def standardize_nulls(df: pd.DataFrame) -> pd.DataFrame:
    '''
    Takes all the various null values and converts them into pd.NA, a null value
    that is compatible with most datatypes to which they may belong.
    Args:
        df (pd.DataFrame): The DataFrame to process.
    Returns:
        A DataFrame whose null values are converted to pd.NA.
    '''
    # Replace null values in non-list cells
    def replace_nulls(value):
        # Handle lists separately
        if isinstance(value, (list, np.ndarray)):
            return [ # Can't directly check truth value of NA
                pd.NA if pd.isna(val) or
                val in ('', 'n/a', 'None') else val
                for val in value
            ]
        elif pd.isna(value) or value == '' or value == 'n/a' or value == 'None':
            return pd.NA
        return value
    # Apply the function element-wise across the DataFrame
    return df.apply(lambda col: col.map(replace_nulls))

def strip_whitespace_from(df: pd.DataFrame) -> pd.DataFrame:
    '''
    Remove whitespace from all applicable columns in a DataFrame.
    Args:
        df (pd.DataFrame): The DataFrame to process.
    Returns:
        The processed DataFrame.
    '''
    for col in df.select_dtypes(include=['string']).columns:
        df[col] = df[col].str.strip()
    return df

# § ============================================================================
# § Data Processing
# § ============================================================================
def compile_cols(
        df: pd.DataFrame,
        col_map: Dict[str, List[str]],
        source_suffix: str='_src'
    ) -> pd.DataFrame:
    '''
    Consolidates version-specific columns into single unified columns.
    Args:
        df (pd.DataFrame): The DataFrame containing version-specific columns.
        column_mapping (Dict[str, List[str]]): A dictionary mapping unified
            column names to version-specific column names to be combined.
        source_suffix (str): The suffix to append to source-version flags
    Returns:
        pd.DataFrame: The updated DataFrame with compiled columns.
    '''
    for unified_col, version_cols in col_map.items():
        # Filter out missing columns
        existing_cols = [col for col in version_cols if col in df.columns]
        non_existant_cols = [
            col for col in version_cols if col not in existing_cols
            ]
        if non_existant_cols:
            print(
                f'Non-existant columns were skipped in the compilation for {unified_col}: {non_existant_cols}'
            )

        if not existing_cols:
            print(f'No existing columns for {unified_col}. Skipping...')

        print(f'Starting to compile {version_cols}...')

        # Back-fill row-wise version-specific values into unified column
        df[unified_col] = df[existing_cols].apply(
            lambda row: row[row.last_valid_index()]
            if row.last_valid_index() else pd.NA,
            axis=1
        )
        print(f'{version_cols} compiled into {unified_col}.')

        print(f'Identifying source of {unified_col}...')
        # Flag the source column
        df[f'{unified_col}{source_suffix}'] = df[existing_cols].apply(
            lambda row: row.last_valid_index().split('_')[-1].upper()
            if row.last_valid_index() else pd.NA,
            axis=1
        )
        print(f'{unified_col}{source_suffix} identified!')

        # Drop version-specific columns after consolidation
        df = df.drop(columns=existing_cols)
    return df

def concat_col(
        df: pd.DataFrame,
        cols: List[str],
        sep: str=' '
    ) -> pd.DataFrame:
    '''
    Concatenates all strings in lists within the DataFrame column.
    Args:
        df (pd.DataFrame): The DataFrame to process.
        col (str): The column whose lists need concatenation.
        sep (str): The separator with which to join the lists' items.
    Returns:
        pd.DataFrame: DataFrame with the column concatenated.
    '''
    def concat_list(lst: Union[List[str], np.ndarray]) -> str:
        if isinstance(lst, (list, np.ndarray)):
            # Filter out empty strings and concatenate non-empty ones
            return sep.join(filter(None, lst))
        elif pd.isna(lst):
            return ''
        else:
            return str(lst)  # Handle non-list cases gracefully, if any
    # Apply the concatenation function to each column
    for col in cols:
        if col in df.columns:  # Ensure the column exists
            df[col] = df[col].apply(concat_list)
    return df

def convert_cols(
        df: pd.DataFrame,
        conversions: Dict[str, List[str]]
    ) -> pd.DataFrame:
    '''
    Converts columns in a DataFrame based on a specified CONVERSIONS dictionary.
    Args:
        df (pd.DataFrame): The DataFrame to process.
        columns (dict): A dictionary of columns and the datatypes to convert
        them to.
    Returns:
        The DataFrame containing the converted columns.
    '''
    for dtype, cols in conversions.items():
        if cols == '*':
            cols = [
                col for col in df.columns
                if col not in df.columns.intersection(
                    conversions.get(dtype, [])
                )
            ]
        for col in cols:
            if col in df.columns:
                try:
                    if dtype.lower() in ['string', 'str', 's', 'txt', 'text']:
                        df[col] = df[col].astype('string').str.strip()
                        print(f'{col} converted to string!')
                    elif dtype.lower() in [
                        'integer', 'int', 'i', 'integer64', 'int64', 'i64',
                        'num', 'number', 'numeric',
                        'num64', 'number64', 'numeric64'
                    ]:
                        df[col] = df[col].astype('Int64')
                    elif dtype.lower() in ['float', 'f', 'double', 'dbl']:
                        df[col] = df[col].astype('Float64')
                        print(f'{col} converted to float!')
                    elif dtype.lower() in [
                        'datetime', 'datetime64', 'dt', 'dt64', 'date'
                    ]:
                        df[col] = pd.to_datetime(
                            df[col], format='mixed', utc=True
                        )
                        print(f'{col} converted to datetime!')
                    elif dtype.lower() in ['boolean', 'bool', 'b']:
                        df[col] = df[col].astype('boolean')
                        print(f'{col} converted to boolean!')
                    elif dtype.lower() in [
                        'categorical', 'category', 'cat', 'c'
                    ]:
                        df[col] = df[col].astype('category')
                        print(f'{col} converted to category!')
                    elif dtype.lower() in ['object', 'obj', 'o']:
                        df[col] = df[col].astype('object')
                        print(f'{col} converted to object!')
                    else:
                        print(
                            f'Unsupported data type "{dtype}" for column "{col}".'
                        )
                except Exception as e:
                    print(f'Error converting column "{col}" to {dtype}: {e}')
    return df

def extract_and_explode(
        df: pd.DataFrame,
        id_col: str,
        cols: List[str],
        name: str
    ) -> pd.DataFrame:
    '''
    Creates a subtable from the given DataFrame with the given columns. The ID
    is the foreign key that connects the subtable back to the original and the
    name helps keep track of the data source should these subtables be merged.
    Args:
        df (pd.DataFrame): The DataFrame to process.
        id_col (str): The column that connects the subtable to the original.
        cols (List[str]): A list of the columns to explode.
        name (str): The name of the subtable.
    Returns:
        An DataFrame whose given columns are exploded across multiple rows.
    '''
    # Validate input columns
    missing_cols = [col for col in cols if col not in df.columns]
    if missing_cols:
        raise ValueError(f'Columns {missing_cols} not found in DataFrame.')
    if id_col not in df.columns:
        raise ValueError(f'ID column "{id_col}" not found in DataFrame.')
    # Copy a subset of the original table
    sub_df = df[[id_col] + cols].copy()
    # Equalize list lengths
    sub_df = harmonize_list_lengths(sub_df, cols)
    # Explode the subtable
    sub_df = sub_df.explode(cols).reset_index(drop=True)
    # Add a source_table column if subtable_name is provided
    if name:
        sub_df['source_table'] = name
    return sub_df

def flatten_cols(df: pd.DataFrame, cols: List[str]) -> pd.DataFrame:
    '''
    Flatten single-item lists in DataFrame columns for which every observation
    is such a list. Any columns whose list cannot be flatten are printed to the
    console.
    Args:
        df (pd.DataFrame): The DataFrame to process.
        cols (List[str]): A list of the columns to flatten.
    Returns:
        pd.DataFrame: The transformed DataFrame, or the original if validation
        fails.
    '''
    def flatten_cols_inner(df: pd.DataFrame, cols: List[str]) -> pd.DataFrame:
        ValueErrors = []
        for col in cols:
            if col not in df.columns:
                ValueErrors.append(
                    f'Column "{col}" does not exist in the DataFrame.'
                )
                continue
            # Check for multi-item lists
            has_invalid_rows = df[col].apply(
                lambda x: isinstance(x, (list, np.ndarray)) and len(x) > 1
            ).any()

            if has_invalid_rows:
                invalid_rows = df[col].apply(
                    lambda x: (isinstance(x, (list, np.ndarray)) and len(x) > 1)
                )
                invalid_indices = invalid_rows[invalid_rows].index.tolist()
                if len(invalid_indices) <= 5:
                    ValueErrors.append(
                        f'Column "{col}" contains multi-item lists. Rows: {invalid_indices}'
                    )
                else:
                    ValueErrors.append(
                        f'Column "{col}" contains multi-item lists. First 5 Rows: {invalid_indices[:5]}...'
                    )
            else:
                # Flatten single-item lists
                df[col] = df[col].apply(
                    lambda x: x[0] if isinstance(
                        x, (list, np.ndarray)
                    ) and len(x) == 1 else x
                )
                print(f'"{col}" has been flattened.')
        # Print errors to the console
        if ValueErrors:
            for error in ValueErrors:
                print(f'Validation error during flattening: {error}')
        return df
    # Try to flatten columns and handle validation errors
    return flatten_cols_inner(df, cols)

def harmonize_list_lengths(
        df: pd.DataFrame,
        cols: List[str],
        padding: Union[pd._libs.missing.NAType, str, int, float]=pd.NA
    ) -> pd.DataFrame:
    '''
    Ensure all list-like columns have the same length across rows. This is
    required if exploding lists across multiple observations to prevent data
    misalignment.
    Args:
        df (pd.DataFrame): The DataFrame to process.
        cols (List[str]): A list of the columns whose lists need equalizing.
        padding: The value to be padded into lists
    Returns:
        pd.DataFrame: A DataFrame containing row-wise equal-length lists
    '''
    # Calculate length of longest list in row
    def pad_row(row: List[str]) -> List[str]:
        max_len = max(
            len(row[col]) for col in cols if isinstance(
                row[col], (list, np.ndarray)
            )
        )
    # Add padding to listed columns to equalize their lengths
        for col in cols:
            if isinstance(row[col], list):
                row[col] = row[col] + [padding] * (max_len - len(row[col]))
        return row
    return df.apply(pad_row, axis=1)

# § ============================================================================
# § CVE-, CVSS-, and EPSS-Specific Processing
# § ============================================================================
def calc_cvss_severity(score: float) -> str:
    if score is None or not isinstance(score, float):
        return np.nan  # Handle missing or invalid scores
    # Map CVSS scores to severity levels
    if score >= 9.0:
        return 'CRITICAL'
    elif score >= 7.0:
        return 'HIGH'
    elif score >= 4.0:
        return 'MEDIUM'
    elif score > 0.0:
        return 'LOW'
    elif score == 0.0:
        return 'NONE'
    else:
        return 'UNKNOWN'

def extract_cvss_metrics(
        df: pd.DataFrame,
        vector_col: str,
    ) -> pd.DataFrame:
    '''
    Extracts CVSS metrics from a vector string column and appends them as new
    columns.
    Args:
        df (pd.DataFrame): The dataframe in which CVSS columns will be found.
        vector_col (str): The name of the column with CVSS vector strings.
    Returns:
        pd.DataFrame: DataFrame with extracted CVSS metrics as new columns.
    '''
    try:
        version = vector_col.split('_')[1]
    except Exception as e:
        print(
            f'Error finding CVSS version number in column passed to "{extract_cvss_metrics.__name__}": {e}'
        )

    # Combine base names and version-specific overrides
    metric_names = CVSS_BASE_METRICS.copy()
    metric_names.update(CVSS_VERSION_SPECIFIC_METRIC_OVERRIDES.get(version, {}))
    # Handle metric value translations
    version_map = TOTAL_CVSS_MAPPINGS[version]
    metrics = version_map['metrics']
    translations = version_map['translations']

    def parse_cvss_vector(vector: Union[str, None]) -> Dict[str, str]:
        '''Parse and translate a CVSS vector string based on its version.'''
        if not isinstance(vector, str):
            return {}
        # Initialize an empty dictionary to hold the parsed metrics
        parsed_metrics = {}
        try:
            pairs = vector.split('/') # Split the vector by '/'
            for pair in pairs:
                if ':' not in pair:
                    print(f'Skipping invalid pair: {pair}')
                    continue # Skip invalid pairs
                key, value = pair.split(':')
                key, value = key.strip(), value.strip()
                print(f"Processing key: '{key}', value: '{value}'")
                if key not in metrics:
                    print(f'Skipping unrecognized key: {key}')  # Log unrecognized keys
                    continue  # Skip keys not in metrics

                if key not in translations:
                    print(f'Missing translation mapping for key: {key}')  # Log missing translations
                    continue  # Skip keys without translations

                if key not in metric_names:
                    print(f'Missing metric name for key: {key}')  # Log missing metric names
                    continue  # Skip keys without metric names

                # Map the value using translations mapping
                translation = translations[key].get(value, None)
                if translation == None:
                    print(f'No translation found for key "{key}" with value "{value}"')
                else:
                    # print(f'Translated "{value}" to "{translation}" for key "{key}"')
                    pass
                parsed_metrics[f'{metric_names[key]}_{version}'] = translation
        except Exception as e:
            print(f'Error parsing vector "{vector}": {e}')
        return parsed_metrics
    # Apply the parser to the vector column
    parsed_metrics = df[vector_col].apply(
        lambda vector: parse_cvss_vector(vector)
    )
    # Convert parsed metrics into a single-row DataFrame
    parsed_df = pd.DataFrame(parsed_metrics.tolist())
    return pd.concat([df, parsed_df], axis=1)

def extract_cvss_severity(
        df: pd.DataFrame,
        score_cols: List[str]
    ) -> pd.DataFrame:
    '''
    Uses a DataFrame's CVSS scores to produce categorical severities.
    Args:
        df (pd.DataFrame): DataFrame to extract the severity categories.
        score_cols (List[str]): Columns containing CVSS scores.
    Returns:
        pd.DataFrame: A DataFrame containing the severity categories.
    '''
    def get_severity(score: float, version: str) -> str:
        '''
        Extracts the severity category based on the CVSS version and score.
        Args:
            score (float): The CVSS score
            version (str): The CVSS version
        Returns:
            str: The severity category.
        '''
        if score is None or not isinstance(score, float):
            return np.nan  # Handle missing or invalid scores
        if version == 'v2':
            if 0.0 <= score <= 3.9:
                return 'Low'
            elif 4.0 <= score <= 6.9:
                return 'Medium'
            elif 7.0 <= score <= 10.0:
                return 'High'
            else:
                return np.nan  # Score out of range for CVSS v2.0
        elif version in ['v3', 'v3_1', 'v4']:  # Same logic for v3.x and v4.0
            if score == 0.0:
                return 'None'
            elif 0.1 <= score <= 3.9:
                return 'Low'
            elif 4.0 <= score <= 6.9:
                return 'Medium'
            elif 7.0 <= score <= 8.9:
                return 'High'
            elif 9.0 <= score <= 10.0:
                return 'Critical'
            else:
                return np.nan
        else:
            return 'Unknown Version'  # Unsupported version
    for col in score_cols:
        # Extract version from the column name using regex
        match = re.search(r'v(\d+\_?\d*)$', col)
        version = 'v' + match.group(1) if match else None
        # Create a new severity column
        severity_col = f'{col}_severity'
        df[severity_col] = df[col].apply(lambda score: get_severity(score, version))
    return df

def extract_max_cvss_score_and_vector(
        df: pd.DataFrame,
        score_col: str,
        vector_col: str
    ) -> pd.DataFrame:
    '''
    Extract the maximum score and its corresponding vector for the specified
    columns. Overwrites the original columns in the DataFrame.
    Args:
        df (pd.DataFrame): The dataframe from which to extract the maximum score
            and vector.
        score_col (str): The column from which to extract the maximum score.
        vector_col (str): The column from which to extract the vector.
    Returns:
        pd.DataFrame: The DataFrame with added maximum score and vector columns.
    '''
    df[score_col], df[vector_col] = zip(*df.apply(
        lambda row: max(zip(row[score_col], row[vector_col]), key=lambda x: x[0]),
        axis=1
    ))
    return df

def filter_cves(
        df: pd.DataFrame,
        search_field: str,
        sensitive_keywords: List[str],
        insensitive_keywords: List[str]
    ) -> pd.DataFrame:
    '''
    Filters a DataFrame of CVEs based on the existence of at least one keyword
    in the search field column.
    Args:
        df (pd.DataFrame): The DataFrame to filter.
        search_field (str): The column to search in for keywords.
        keywords (List[str]): The keywords to look for in the search field.
    Returns:
        pd.DataFrame: The filtered DataFrame.
    '''
    if search_field not in df.columns:
        raise ValueError(f'Column "{search_field}" not found in DataFrame.')

    # Build regex patterns for case-sensitive and case-insensitive keywords
    case_sensitive_pattern = '|'.join(f'\\b{re.escape(kw)}\\b' for kw in sensitive_keywords)
    case_insensitive_pattern = '|'.join(f'(?i)\\b{re.escape(kw)}\\b' for kw in insensitive_keywords)

    # Define helper functions for matching
    def find_case_sensitive_match(text: str) -> str:
        if not isinstance(text, str):
            return None
        match = re.search(case_sensitive_pattern, text)
        return match.group(0) if match else None

    def find_case_insensitive_match(text: str) -> str:
        if not isinstance(text, str):
            return None
        match = re.search(case_insensitive_pattern, text)
        return match.group(0) if match else None

    # Apply both patterns separately and record the first match
    df['matched_keyword'] = df[search_field].apply(
        lambda text: find_case_sensitive_match(text)
        or find_case_insensitive_match(text)
    )

    # Filter rows where a match was found
    return df[df['matched_keyword'].notna()].reset_index(drop=True)

def impute(df: pd.DataFrame, impute_cases: Dict[str, str]) -> pd.DataFrame:
    '''
    Impute missing values according to the impute_cases dictionary.
    Args:
        df (pd.DataFrame): The DataFrame containing data to impute.
        impute_cases (Dict[str, str]): Dictionary specifying imputation rules
            for each target column.

            Example format:
            {
                'epss_30': {
                    'required': ['epss_0', 'epss_60'],
                    'method': 'mean'
                },
                'percentile_0': {
                    'required': ['percentile_30', 'percentile_60'],
                    'method': 'sigmoid'
                }
            }

    Returns:
        The DataFrame containing imputed values.
    '''
    df = df.copy()  # Avoid modifying original dataframe

    # Define sigmoid function
    def sigmoid(
            time_point: float,
            growth_rate: float,
            midpoint: float
        ) -> float:
        return 1 / (1 + np.exp(-growth_rate * (time_point - midpoint)))

    # Fit a sigmoid curve to known data points
    def fit_sigmoid(
            known_time_points: np.ndarray,
            known_values: np.ndarray
        ) -> Union[Tuple, None]:
        '''
        Fits a sigmoid curve to the known data points and returns the best-
        fitting paramaters.
        '''
        if len(known_values) < 2 or len(set(known_values)) == 1:
            return None

        try:
            params, _ = curve_fit(
                sigmoid,
                known_time_points,
                known_values,
                bounds=([-10, -np.inf], [10, np.inf])
            )
            return params # Returns growth_rate and midpoint
        except RuntimeError:
            return None # Failed to fit

    def predict_sigmoid(
            target_time_point: float,
            known_time_points: np.ndarray,
            known_values: np.ndarray,
            full_col: pd.Series
    ) -> float:
        '''Predicts a missing value using a fitted sigmoid model.'''
        col_mean = np.clip(full_col.mean(), 0, 1)

        if len(known_values) < 2:
            return col_mean

        if len(set(known_values)) == 1:
            return known_values[0]

        fitted_parameters = fit_sigmoid(known_time_points, known_values)
        if fitted_parameters is not None:
            growth_rate, midpoint = fitted_parameters
            predicted_value = sigmoid(target_time_point, growth_rate, midpoint)
            return np.clip(predicted_value, 0, 1)
        else:
            return col_mean

    def extract_time(col_name: str) -> int:
        '''
        Extracts the numeric time point from a column name with format col_n.
        '''
        return int(col_name.split('_')[-1])

    df['imputation'] = pd.NA

    for target_col, rule in impute_cases.items():
        required_cols = rule['required']
        method = rule['method']

        # Create a boolean mask for rows where target_col is missing but
        # required_cols are present
        mask = df[target_col].isna() & df[required_cols].notna().all(axis=1)

        if method == 'mean':
            df.loc[mask, target_col] = df.loc[mask, required_cols].mean(axis=1)
            df.loc[mask, 'imputation'] = df[mask].apply(lambda row: f'{target_col.upper()}: MEAN ({row[target_col]:.4f})', axis=1) 

        elif method == 'sigmoid':
            target_time_point = extract_time(target_col)

            # Apply sigmoid imputation
            for row_index in df[mask].index:
                known_time_points = np.array(
                    [extract_time(col) for col in required_cols]
                )
                known_values = df.loc[row_index, required_cols].values
                full_col = df[target_col]

                if len(known_values) < 1:
                    df.at[row_index, 'imputation'] = 'IMPOSSIBLE'
                    continue

                df.at[row_index, target_col] = predict_sigmoid(
                    target_time_point,
                    known_time_points,
                    known_values,
                    full_col
                )
                df.at[row_index, 'imputation'] = f'{target_col}: SIGMOID ({df.at[row_index, target_col]:.4f})'
    return df

    # # Case 1: Interpolate missing epss_30
    # boolmask1 = df['epss_30'].isna() & df['epss_0'].notna() & df['epss_60'].notna()
    # df.loc[boolmask1, 'epss_30'] = (
    #     df.loc[boolmask1, 'epss_0'] + df.loc[boolmask1, 'epss_60']
    # ) / 2

    # # Case 2: Extrapolate backwards missing epss_0
    # boolmask2 = df['epss_0'].isna() & df['epss_30'].notna() & df['epss_60'].notna()
    # df.loc[boolmask2, 'epss_0'] = df.loc[boolmask2, 'epss_30'] - (
    #     df.loc[boolmask2, 'epss_60'] - df.loc[boolmask2, 'epss_30']
    # )

    # # Case 3: Extrapolate forward missing epss_60
    # boolmask3 = df['epss_60'].isna() & df['epss_30'].notna() & df['epss_0'].notna()
    # df.loc[boolmask3, 'epss_60'] = df.loc[boolmask3, 'epss_30'] + (
    #     df.loc[boolmask3, 'epss_30'] - df.loc[boolmask3, 'epss_0']
    # )

    return df

# § ============================================================================
# § Validation & Inspection
# § ============================================================================
def id_hashable_cols(df: pd.DataFrame) -> List[str]:
    '''
    Returns a list of columns whose data is hashable for certain methods that
    require comparison evaluations like drop_duplicates.
    Args:
        df (pd.DataFrame): The DataFrame to process.
    '''
    hashable_cols = []
    for col in df.columns:
        try:
            # Test if all elements in column are hashable
            df[col].apply(hash) # This will raise an error for unhashable types
            hashable_cols.append(col)
        except TypeError:
            print(f'"{col}" contains unhashable types')
            pass
    return hashable_cols

def inspect_col_items(df: pd.DataFrame, col: str, start=0, end=None) -> None:
    '''
    Prints the type of items found in the given column.
    '''
    # Check each row in the column
    end = end if end is not None else len(df)
    for idx, cell in df[col].iloc[start:end].items():
        if isinstance(cell, (list, np.ndarray)):
            # Get the set of unique types in the list
            types = {type(item) for item in cell}
            print(f'Col: {col} | Row {idx} | Data: {cell} | Types: {types}')
        else:
            print(
                f'Col: {col} | Row {idx} | Data: {cell} | Type: {type(cell)}'
            )

def validate_cve_id(primary: str, backup: Union[str, List[str]]=None) -> str:
    '''
    Validates and formats CVE IDs to follow 'CVE-YYYY-XXXXXXX' by attempting to
    remedy a variety of potential malformations.
    Args:
        cve_id (str): The CVE ID to validate and format
        backup (str or List[str]): Alternative CVE ID location to check if main
            is empty
    Returns: A validated CVE ID string
    '''
    # Regex pattern for CVE ID
    pattern = r'(?i)CVE-(1999|20[0-9]{2})-(\d{4,7})'
    primary = str(primary)
    # Check if CVE ID matches the pattern
    match = re.search(pattern, primary)
    if match:
        return match.group(0).upper() # Valid format, return as is
    # Try to fix common issues (e.g., missing 'CVE-', extra spaces, lowercase)
    try:
        # Extract digits and check the format
        fixed_id = re.sub(r'\s+', '', primary)
        fixed_id = fixed_id.upper()
        fixed_id = re.sub(r'^([0-9]{4})-([0-9]+)$', r'CVE-\1-\2', fixed_id)

        # Check if ordinal section of ID needs zero-padding
        if re.match(r'(?i)CVE-(1999|20[0-9]{2})-(\d+)'):
            year, ordinal = fixed_id.group(0).split('-')[1:]
            fixed_ordinal = ordinal.zfill(4)
            fixed_id = f'CVE-{year}-{fixed_ordinal}'

        # Check if ID matches the pattern after fixing
        if re.search(pattern, fixed_id):
            return fixed_id
    except:
        pass
    # If the ID is still invalid, look through the backup
    if isinstance(backup, (list, np.ndarray)) and len(backup) > 0:
        for item in backup:
            item = str(item).strip()
            backup_match = re.search(pattern, item)
            if backup_match:
                year, ordinal = backup_match.group(0).split('-')[1:]
                fixed_ordinal = ordinal.zfill(4)
                return f'CVE-{year}-{fixed_ordinal}'
    return pd.NA
