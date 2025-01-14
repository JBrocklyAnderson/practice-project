"""
This script takes the XML file offered by MITRE as the storehouse for Common
Weakness Enumeration (CWE) information and extracts data relevant to the
project's analysis. This data is cleaned and merged into a final dataset form
via other scripts.
"""

import xml.etree.ElementTree as ET
import pandas as pd
from typing import List, Dict, Union
from utils import save_data

# XML namespaces
NS = {
        'ns': 'http://cwe.mitre.org/cwe-7',
        'xhtml': 'http://www.w3.org/1999/xhtml',
        'xsi': 'http://www.w3.org/2001/XMLSchema-instance'
    }


def parse_xml(file_path: str) -> ET.ElementTree:
    """Parse the provided XML file and return the ElementTree object."""
    try:
        return ET.parse(file_path)
    except Exception as e:
        raise ValueError(f'Failed to parse XML file: {e}')

# Define utility functions for readable extractions
def get_el(parent_tag, tag, namespace, default=''):
    # Retrieve text from between tags
    child_tag = parent_tag.find(tag, namespace)
    return (
        child_tag.text or default
    ).strip() if child_tag is not None else default

def get_list_of_att(parent_tag, attribute):
    # Find the attribute in each child tag of the parent element
    return [tag.get(attribute).strip() for tag in parent_tag if tag.get(attribute)]

# def get_list_of_el(elements):
#     # Retrieve text from each child element of the parent
#     return [elem.text.strip() for elem in elements if elem.text]

def extract_cwe_data(
        tree: ET.ElementTree
    ) -> List[Dict[str, Union[str, List[str]]]]:
    """Extract CWE data from the parsed XML tree."""
    root = tree.getroot()
    data = []
    weaknesses = root.findall('.//ns:Weakness', NS)

    for weakness in weaknesses:
        cwe_data = {
            'cwe_id': weakness.get('ID', '').strip(),
            'cwe_name': weakness.get('Name', '').strip(),
            'cwe_desc': get_el(weakness, 'ns:Description', NS),
            'cwe_desc_extended': get_el(
                weakness, 'ns:Extended_Description', NS
            ),
            'cwe_related_id': get_list_of_att(
                weakness.findall('.//ns:Related_Weakness', NS), 'CWE_ID'
            ),
            'cwe_nature_of_rel': get_list_of_att(
                weakness.findall('.//ns:Related_Weakness', NS), 'Nature'
            ),
            'cwe_bg_details': [
                get_el(bg_detail, 'ns:Background_Detail', NS)
                for bg_detail in weakness.findall(
                    './/ns:Background_Details', NS
                )
            ],
            'cwe_introduction': [
                get_el(intro, 'ns:Phase', NS)
                for intro in weakness.findall('.//ns:Introduction', NS)
            ],
            'cwe_exploit_likelihood': get_el(
                weakness, 'ns:Likelihood_Of_Exploit', NS
            ),
            'cwe_consequence_scope': [
                get_el(consequence_s, 'ns:Scope', NS)
                for consequence_s in weakness.findall('.//ns:Consequence', NS)
            ],
            'cwe_consequence_impact': [
                get_el(consequence_i, 'ns:Impact', NS)
                for consequence_i in weakness.findall('.//ns:Consequence', NS)
            ],
            'cwe_consequence_note': [
                get_el(consequence_n, 'ns:Note', NS)
                for consequence_n in weakness.findall('.//ns:Consequence', NS)
            ],
            'cwe_detect_method': [
                get_el(method, 'ns:Method', NS)
                for method in weakness.findall('.//ns:Detection_Method', NS)
            ],
            'cwe_detect_desc': [
                get_el(desc, 'ns:Description', NS)
                for desc in weakness.findall('.//ns:Detection_Method', NS)
            ],
            'cwe_detect_effectiveness': [
                get_el(effect, 'ns:Effectiveness', NS)
                for effect in weakness.findall('.//ns:Detection_Method', NS)
            ],
            'cwe_detect_effect_notes': [
                get_el(effect_note, 'ns:Description', NS)
                for effect_note in weakness.findall(
                    './/ns:Detection_Method', NS
                )
            ],
            'cwe_miti_phase': [
                get_el(phase, 'ns:Phase', NS)
                for phase in weakness.findall('.//ns:Mitigation', NS)
            ],
            'cwe_miti_desc': [
                get_el(desc, 'ns:Description', NS)
                for desc in weakness.findall('.//ns:Mitigation', NS)
            ],
            'cwe_miti_effect': [
                get_el(effect, 'ns:Effectiveness', NS)
                for effect in weakness.findall('.//ns:Mitigation', NS)
            ],
            'cwe_miti_effect_notes': [
                get_el(effect_notes, 'ns:Effectiveness_Notes', NS)
                for effect_notes in weakness.findall('.//ns:Mitigation', NS)
            ]
        }
        data.append(cwe_data)
    return data

def extract_applicable_platform_data(tree: ET.ElementTree) -> pd.DataFrame:
    root = tree.getroot()
    weaknesses = root.findall('.//ns:Weakness', NS)

    platform_data = []
    for weakness in weaknesses:
        cwe_id = weakness.get('ID', '').strip()
        for platform_type in [
            'Language',
            'Architecture',
            'Operating_System',
            'Technology'
        ]:
            for platform in weakness.findall(f'.//ns:{platform_type}', NS):
                platform_data.append({
                    'cwe_id': cwe_id,
                    'type': platform_type,
                    'name': platform.get('Name', '').strip(),
                    'class': platform.get('Class', '').strip(),
                    'prevalence': platform.get('Prevalence', '').strip()
                })
    return platform_data

def to_dataframe(
        data: List[Dict[str, Union[str, List[str]]]]
    ) -> pd.DataFrame:
    """
    Process the extracted CWE data and convert it into a Pandas DataFrame.
    """
    return pd.DataFrame(data)

def run_cwe_extraction(
        input_file: str,
        output_file: str,
        file_format: str='parquet'
    ):
    """Orchestrate the parsing, extraction, and saving of CWE data."""
    tree = parse_xml(input_file)
    extracted_data = extract_cwe_data(tree)
    df = to_dataframe(extracted_data)
    save_data(df, output_file, file_format)

    # Handle applicable platform data separately
    extracted_platform_data = extract_applicable_platform_data(tree)
    platform_df = to_dataframe(extracted_platform_data)
    save_data(
        platform_df,
        f'data/intermediate/mitre/cwe/cwe_platform_extracted.{file_format}',
        file_format
    )

# if __name__ == '__main__':
#     run_cwe_extraction()