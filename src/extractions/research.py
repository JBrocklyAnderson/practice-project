'''
This script takes whatever is in the JSON data and prints it into a CSV file for
easy readability.
'''
import pandas as pd

json_data = {
    'searches': [
        {
            'search_id': 1,
            'search_date': '2025-03-06',
            'search_source': 'Google',
            'results': [
                {
                    'title': 'ICS-LTU2022: A dataset for ICS vulnerabilities',
                    'description': 'The research collects vulnerability data from public sources, mainly the NVD and CVE. The dataset compiled from these sources is comprehensive, encompassing a wide range of ICS vulnerabilities.',
                    'link': 'https://www.sciencedirect.com/science/article/pii/S0167404824004486',
                    'relevant': 'True'
                }
            ]
        },
        {
            'search_id': 2,
            'search_date': '2025-03-06',
            'search_source': 'Chat GPT',
            'results': [
                {
                    'title': 'WUSTL-IIOT-2018 Dataset',
                    'description': 'Developed by Washington University in St. Louis, this dataset was built using a SCADA system testbed designed to emulate real-world industrial systems. It includes data from realistic cyber-attacks, focusing on reconnaissance attacks where the network is scanned for possible vulnerabilities. While the dataset captures various attack scenarios, it does not explicitly map these to specific CVEs.',
                    'link': 'https://www.cse.wustl.edu/~jain/iiot/index.html',
                    'relevant': 'no'
                },
                {
                    'title': 'Learning From Vulnerabilities - Categorising, Understanding and Detecting Weaknesses in Industrial Control Systems',
                    'description': "The 'Learning from Vulnerabilities' Dataset was curated by scraping CISA ICS-CERT Advisories, the NIST NVD CVE feeds, MITRE CVE exports and the MITRE CWE list. The workflow that imports the data held in these sources to form our Dataset is given in our paper. This Dataset contains all ICS advisories between 2011 and March 2020.",
                    'link': 'https://uob-ritics.github.io/learning-from-vulnerabilities/',
                    'relevant': 'True'
                }
            ]
        },
        {
            'search_id': 3,
            'search_date': '2025-03-07',
            'search_source': 'GitHub',
            'results': [
                {
                    'title': 'ICS Advisory Project',
                    'description': 'The ICS Advisory Project is an open-source project to provide clean and usable DHS CISA ICS Advisories data in Comma Separated Value (CSV) format.',
                    'link': 'https://github.com/icsadvprj/ICS-Advisory-Project?tab=readme-ov-file',
                    'relevant': 'True',
                    'API': 'True'
                },
                {
                    'title': 'NVD-API-CVE-Fetcher-for-ICS-CVEs',
                    'description': 'This repository contains a PowerShell script that enables the retrieval of Common Vulnerabilities and Exposures (CVEs) specifically related to Industrial Control Systems (ICS) using the NVD (National Vulnerability Database) API.',
                    'link': 'https://github.com/salahlouffidi/NVD-API-CVE-Fetcher-for-ICS-CVEs',
                    'relevant': 'True'
                },
                {
                    'title': 'CVE-2012-1831',
                    'description': 'A single ICS-related CVE.',
                    'link': 'https://github.com/Astrowmist/POC-CVE-2012-1831',
                    'relevant': 'True'
                },
                {
                    'title': 'CVE-2018-11311',
                    'description': 'A single ICS-related CVE.',
                    'link': 'https://github.com/EmreOvunc/mySCADA-myPRO-7-Hardcoded-FTP-Username-and-Password',
                    'relevant': 'True'
                },
                {
                    'title': 'Unauthenticated-RCE-FUXA-CVE-2023-33831',
                    'description': 'A single ICS-related CVE.',
                    'link': 'https://github.com/rodolfomarianocy/Unauthenticated-RCE-FUXA-CVE-2023-33831',
                    'relevant': 'True'
                },
                {
                    'title': 'CVE-2021-26828_ScadaBR_RCE',
                    'description': 'A single ICS-related CVE.',
                    'link': 'https://github.com/hev0x/CVE-2021-26828_ScadaBR_RCE',
                    'relevant': 'True'
                }
            ]
        },
        {
            'search_id': 4,
            'search_date': '2025-03-06',
            'search_source': 'Kaggle',
            'results': []
        }
    ]
}

# Flatten JSON data to a list of dictionaries
flat_data = []
for search in json_data['searches']:
    search_info = {'search_id': search['search_id'], 'search_date': search['search_date'], 'search_source': search['search_source']}
    for result in search['results']:
        combined_info = {**search_info, **result}
        flat_data.append(combined_info)

# Convert to DataFrame
df = pd.DataFrame(flat_data)

# Write DataFrame to Excel
df.to_csv('data/research/search_results.csv', index=None)

print('Research spreadsheet created successfully!')