'''
This is a script dedicated to preprocessing the ICS dataset and getting it ready
to be compiled into the full dataset for analysis.
'''
import pandas as pd
import numpy as np
from utils import *

COL_TYPES = {
    'string': [],
    'category': [],
}


def run_ics_preprocessing(
    input_file: str,
    output_file: str,
    file_format: str='parquet'
) -> None:
    # Load data
    df = pd.read_csv(input_file)
    




    # Save data
    save_data(df, output_file, file_format)