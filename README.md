# Patch Prioritization Analysis

## Project Overview
This project aims to analyze and prioritize software patches based on various criteria such as severity, exploitability, affected systems, and historical risk factors. By leveraging machine learning and data analytics, this project helps security teams focus on the most critical patches first.

The last time MITRE's CVE Project filebase was pulled into the local repository from which this project extracts crucial CVE data was Wednesday, December 11, 2024.

## Table of Contents
- [Project Overview](#project-overview)
- [Data Sources](#data-sources)
- [Data Collection & Processing](#data-collection--processing)
    - [MITRE](#mitre)
        - [CVE](#cve)
        - [CWE](#cwe)
    - [NVD](#nvd)
    - [FIRST](#first)
    - [ExploitDB](#exploitdb)
    - [PoC-in-GitHub](#poc-in-github)
- [Data Dictionary](#data-dictionary)
    - [Focused Dictionary](#focused-dictionary)
    - [General Dictionary](#general-dictionary)
- [Installation](#installation)
    - [Setting up the Environment](#setting-up-the-environment)
        - [For Conda Users](#for-conda-users)
        - [For Pip Users](#for-pip-users)
- [Usage](#usage)
- [Methodology](#methodology)
- [Results](#results)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

## Data Sources
The dataset used for this analysis was compiled from multiple sources, both publically and privately curated:
- **Vulnerability Databases** - Pulled CVE data from [MITRE's CVE Project](https://github.com/CVEProject/cvelistV5), [NIST's NVD API](https://nvd.nist.gov/developers/start-here), and [CISA's KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
- **Exploit Databases**: Mined public exploit databases [Exploit DB](https://www.exploit-db.com/) and the [Nomi-Sec's Proof-of-Concept GitHub Repository](https://github.com/nomi-sec/PoC-in-GitHub/tree/master).


## Data Collection & Preprocessing
General preprocessing steps were taken to ensure the removal of typos, the standardization of categorical data and attribute names, the scrubbing of extraneous whitespace, the validation of data formats and date ranges, the dropping of duplicates, the compilation of multiple related string variables into a single attribute with longer data, the extraction and explosion of subtables based on listed columns, the standardization of null values, the conversion of data types into those workable with the project's tech stack, and more specialized steps according to the idiosyncracies of the data source.

The general process of extracting and combining all this information can be found in this paragraph. Following along with the pipeline diagram may help keep track of when and where merged data products are coming from. Generally speaking, data was extracted from each of the sources and cleaned up independently of each other before being merged. This primarily occurs within the `src` directory and is connected to the CLI, but this was not possible in all cases.
1. The first step was to extract and clean the CVE data pulled from MITRE.
2. Next was the extractiona and cleaning of CWE data.
    - The preprocessing of these two data sources produced several subtables that are not a part of the final analysis (yet).
3. Then, EPSS data was extracted and cleaned from FIRST's API.
4. CISA's KEV catalogue was the next dataset to be cleaned and prepared for merging.
5. Now, the PoC-in-GitHub repository was pulled into the project's data files, and from there were extracted CVEs and their exploit code data.
6. At this point, an interactive notebook was created to extract exploit code date from ExploitDB, since they don't offer an official API and it was necessary to use a community-built package that could not be handled by the Conda environment the pipeline operates in (it's installed via `pip`). This is actually what prevents a fully-automated pipeline at the current moment. This notebook also outwardly merges into the extracted CVEs the cleaned PoC-in-GitHub dataset, then merges CISA's KEV into the product of the first merge, now a collection of **exploit data** that forms the backbone of the project's analysis.
7. In the final compilation, the CVE data from MITRE is merged into the exploit data, EPSS data is merged into this product, and NVD data is merged into that product. All of these merges are conducted leftwardly. From here, the dataset is filtered further down into two distinct versions: *focused* and *general*.

![Data Pipeline Diagram](pipeline_diagram.svg)

### MITRE

#### CVE
The entire database from MITRE's CVE project—some $280,000+$ JSON files—was pulled into the raw data directory of the project and an extraction script was designed to pull out data relating to a CVE's ID, description, discovery, and solution. Many features were extracted from CVSS vector strings including a CVE's attack vector and complexity, collateral damage, authentication requirements, and more, all of which can be found in the [data dictionary](#data-dictionary) below. Most were dropped from the focused dataset to hone in on the project's variables of interest.

#### CWE
The [CWE List Version 4.16](https://cwe.mitre.org/data/index.html) is pulled into the project as an XML file from MITRE that was used to extract CWE mappings and their IDs, descriptions, and other relevant information.

### NVD
An API client that uses a list of CVEs to communicate with the NVD's database was built for the purposes of gathering publication dates and additional CVSS scores not available from MITRE. The dates were merged into the dataset on condition that the final publication date attribute took whichever date occured earlier from either MITRE or the NVD.

### FIRST
Another API client was built to extract EPSS data for the project's core CVEs at various dates starting from the moment in which the CVE's first proof-of-concept exploit code was published.

### ExploitDB
A random sample of $20%$ of the CVEs (approx. $51,600$) were checked on ExploitDB to determine the number of exploit codes they had available and the date of the first one that was published.

### PoC-in-GitHub
Nomi Sec's GitHub repository was used to pulled as many CVEs with exploit codes into the project as possible, keeping data related to their occurence in numbers and the date of the soonest one that was published.

## Data Dictionary
Below is a set of two dictionaries describing all of the variables incorporated into the project's final dataset and its data sources. The general dictionary is collapsed by default because of it's lengthy nature.

### Focused Dictionary
| Attribute | Description | Data Type | Example Values | Source |
|-----------|-------------|-----------|----------------|--------|
| `cve_id` | Unique identifier for each CVE | String | `CVE-2024-1204` | MITRE, PoC-in-GitHub, and/or ExploitDB |
| `date_public` | Date the CVE was published on MITRE | Datetime | `2024-04-15` | MITRE |
| `origin` | CVE's original data source | Categorical | `poc_xdb_kev` | PoC-in-GitHub, ExploitDB, and/or KEV  |
| `cvss` | CVSS score (newer versions prioritized) | Float | `7.2` | MITRE and/or NVD |
| `cvss_severity' | Categorical representation of CVSS score | Categorical|  `HIGH` | MITRE and/or NVD |
| `cvss_src' | CVSS score version (newer versions prioritized) | Categorical | `V3` | MITRE and/or NVD |
| `exploit_count` | Number of exploit codes found on ExploitDB and GitHub | Float | `2` | PoC-in-GitHub and ExploitDB |
| `days_to_poc_exploit` | Days from CVE publication to date of first exploit code | Float | `16` | PoC-in-GitHub and ExploitDB |
| `exploitation_date_0` | Date of first exploit code publication | Datetime | `1996-06-01 00:00:00+0000` | PoC-in-GitHub and ExploitDB |
| `epss_0` | EPSS score on `exploitation_0` | Float | `0.8808` | FIRST |
| `percentile_0` | Percentile of `epss_0` score relative to all scores | Float | `0.98791` | FIRST |
| `exploitation_date_30` | Date $60$ days after first exploit code publication | Datetime | `1996-07-01 00:00:00+0000` | PoC-in-GitHub and ExploitDB |
| `epss_30` | EPSS score $30$ days after `exploitation_0` | Float | `0.89391` | FIRST |
| `percentile_30` | Percentile of `epss_30` score relative to all scores | Float | `0.99004` | FIRST |
| `exploitation_date_60` | Date $60$ days after first exploit code publication | Datetime | `1996-07-31 00:00:00+0000` | PoC-in-GitHub and ExploitDB |
| `epss_60` | EPSS score $60$ days after `exploitation_0` | Float | `0.89537` |  FIRST |
| `percentile_60` | Percentile of `epss_60` score relative to all scores | Float | `0.99025` | FIRST |
| `change_0_to_30` | $%$ change between `epss_0` and `epss_30` | Float | `1.4884196185286052` | FIRST |
| `change_30_to_60` | $%$ change between `epss_30` and `epss_60` | Float | `0.02770395756164053` | FIRST |
| `change_0_60` | $%$ change between `epss_0` and `epss_60` | Float | `0.016415307274026673` | FIRST |

### General Dictionary
<details>

<summary>
Expand the dictionary
</summary>

All of the `_src`-appended columns prioritize the newest version of CVSS that the value was found within if it was found in more than one version.
| Attribute | Description | Data Type | Example Values | Source |
|-----------|-------------|-----------|----------------|--------|
| `cve_id` | Unique identifier for each CVE | String | `CVE-2024-1204` | MITRE, PoC-in-GitHub, and/or ExploitDB |
| `date_public` | Date the CVE was published on MITRE | Datetime | `2024-04-15` | MITRE |
| `origin` | CVE's original data source | Categorical | `poc_xdb_kev` | PoC-in-GitHub, ExploitDB, and/or KEV  |
| `cvss` | CVSS score (newer versions prioritized) | Float | `7.2` | MITRE and/or NVD |
| `cvss_severity' | Categorical representation of CVSS score | Categorical|  `HIGH` | MITRE and/or NVD |
| `cvss_src' | CVSS score version (newer versions prioritized) | Categorical | `V3` | MITRE and/or NVD |
| `exploit_count` | Number of exploit codes found on ExploitDB and GitHub | Float | `2` | PoC-in-GitHub and ExploitDB |
| `days_to_poc_exploit` | Days from CVE publication to date of first exploit code | Float | `16` | PoC-in-GitHub and ExploitDB |
| `exploitation_date_0` | Date of first exploit code publication | Datetime | `1996-06-01 00:00:00+0000` | PoC-in-GitHub and ExploitDB |
| `epss_0` | EPSS score on `exploitation_0` | Float | `0.8808` | FIRST |
| `percentile_0` | Percentile of `epss_0` score relative to all scores | Float | `0.98791` | FIRST |
| `exploitation_date_30` | Date $60$ days after first exploit code publication | Datetime | `1996-07-01 00:00:00+0000` | PoC-in-GitHub and ExploitDB |
| `epss_30` | EPSS score $30$ days after `exploitation_0` | Float | `0.89391` | FIRST |
| `percentile_30` | Percentile of `epss_30` score relative to all scores | Float | `0.99004` | FIRST |
| `exploitation_date_60` | Date $60$ days after first exploit code publication | Datetime | `1996-07-31 00:00:00+0000` | PoC-in-GitHub and ExploitDB |
| `epss_60` | EPSS score $60$ days after `exploitation_0` | Float | `0.89537` |  FIRST |
| `percentile_60` | Percentile of `epss_60` score relative to all scores | Float | `0.99025` | FIRST |
| `change_0_to_30` | $%$ change between `epss_0` and `epss_30` | Float | `1.4884196185286052` | FIRST |
| `change_30_to_60` | $%$ change between `epss_30` and `epss_60` | Float | `0.02770395756164053` | FIRST |
| `change_0_60` | $%$ change between `epss_0` and `epss_60` | Float | `0.016415307274026673` | FIRST |
| `cvss_vector` | CVSS vector string (newer versions prioritized) | String | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | MITRE |
| `cve_desc`  | Description of the CVE | String | `The Meta Box WordPress plugin before 5.9.4 does not prevent users with at least the contributor role from access arbitrary custom fields assigned to other user's posts.` | MITRE |
| `mitre_cve_res_date` | Date the CVE was reserved | Datetime | `2024-02-02` | MITRE |
| `solution` | How to solve the CVE | String | `The following software releases have been updated to resolve these specific issues: Contrail 2.21.4, 3.0.3.4, 3.1.4.0, 3.2.5.0 and all subsequent releases.` | MITRE |
| `cve_discovery` | How the CVE was discovered | String | `EXTERNAL` | MITRE |
| `ssvc_exploitation` | Exploitation status of CVE in the SSVC scoring system | Categorical | `ACTIVE` | MITRE |
| 'ssvc_automable` | Automatability of the CVE's exploitation in the SSVC scoring system | Categorical | `YES` | MITRE |
| 'ssvc_tech_impact` | System impact of the CVE | Categorical in the SSVC scoring system | `PARTIAL` | MITRE |
| `attack_complexity` | Measures the complexity of the attack required to exploit the CVE | Categorical | `MEDIUM` | MITRE |
| `attack_complexity_src` | Tracks the source version of the exploitation's complexity | Categorical | `V4` | MITRE |
| `attack_requirements` | Conditions necessary for CVE exploitation to occur | Categorical | `PRESENT` | MITRE |
| `attack_requirements_src` | Tracks the source version of these conditions | Categorical | `V3` | MITRE |
| `attack_vector` | Reflects the context by which the CVE is exploitable | Categorical | `NETWORK` | MITRE |
| `attack_vector_src` | Tracks the source version of this context | Categorical | `NETWORK` | MITRE |
| `authentication` | Indicates if authentication is required for exploitation | Categorical | `NONE` | MITRE |
| `authentication_src` | Tracks the source version of authentication requirement | Categorical | `V3` | MITRE |
| `automatable` | Whether the CVE's exploitation can be automated | Categorical | `YES` | MITRE |
| `automatable_src` | Tracks the source version of automatable status | Categorical | `V3` | MITRE |
| `availability` | Measures impact on system availability if CVE is exploited | Categorical | `HIGH` | MITRE |
| `availability_src` | Tracks the source version of availability impact | Categorical | `V3` | MITRE |
| `confidentiality` | Measures impact on data confidentiality if CVE is exploited | Categorical | `LOW` | MITRE |
| `confidentiality_src` | Tracks the source version of confidentiality impact | Categorical | `V3` | MITRE |
| `exploit_maturity` | Maturity level of known exploits for the CVE | Categorical | `PROOF-OF-CONCEPT` | MITRE |
| `exploit_maturity_src` | Tracks the source version of exploit maturity | Categorical | `V3` | MITRE |
| `integrity` | Measures impact on data integrity if CVE is exploited | Categorical | `HIGH` | MITRE |
| `integrity_src` | Tracks the source version of integrity impact | Categorical | `V3` | MITRE |
| `privileges_required` | Level of privileges required to exploit CVE | Categorical | `LOW` | MITRE |
| `privileges_required_src` | Tracks the source version of privileges requirement | Categorical | `V3` | MITRE |
| `recovery` | Effort needed to recover from exploitation | Categorical | `HIGH` | MITRE |
| `recovery_src` | Tracks the source version of recovery effort | Categorical | `V3` | MITRE |
| `remediation_level` | Readiness of a remediation for the CVE | Categorical | `OFFICIAL-FIX` | MITRE |
| `remediation_level_src` | Tracks the source version of remediation level | Categorical | `V3` | MITRE |
| `report_confidence` | Confidence level in the CVE report | Categorical | `CONFIRMED` | MITRE |
| `report_confidence_src` | Tracks the source version of report confidence | Categorical | `V3` | MITRE |
| `response_effort` | Effort required to respond to CVE | Categorical | `MODERATE` | MITRE |
| `response_effort_src` | Tracks the source version of response effort | Categorical | `V3` | MITRE |
| `safety` | Measures impact on safety-critical systems | Categorical | `LOW` | MITRE |
| `safety_src` | Tracks the source version of safety impact | Categorical | `V3` | MITRE |
| `scope` | Whether the CVE affects systems beyond the initial target | Categorical | `CHANGED` | MITRE |
| `scope_src` | Tracks the source version of scope impact | Categorical | `V3` | MITRE |
| `sub_sys_availability` | Availability impact at the subsystem level | Categorical | `HIGH` | MITRE |
| `sub_sys_availability_src` | Tracks the source version of subsystem availability impact | Categorical | `V3` | MITRE |
| `sub_sys_confidentiality` | Confidentiality impact at the subsystem level | Categorical | `LOW` | MITRE |
| `sub_sys_confidentiality_src` | Tracks the source version of subsystem confidentiality impact | Categorical | `V3` | MITRE |
| `sub_sys_integrity` | Integrity impact at the subsystem level | Categorical | `MEDIUM` | MITRE |
| `sub_sys_integrity_src` | Tracks the source version of subsystem integrity impact | Categorical | `V3` | MITRE |
| `urgency` | Urgency of applying the patch | Categorical | `CRITICAL` | MITRE |
| `urgency_src` | Tracks the source version of urgency status | Categorical | `V3` | MITRE |
| `user_interaction` | Whether user interaction is needed for exploitation | Categorical | `REQUIRED` | MITRE |
| `user_interaction_src` | Tracks the source version of user interaction requirement | Categorical | `V3` | MITRE |
| `value_density` | Importance of the affected system based on its data | Categorical | `HIGH` | MITRE |
| `value_density_src` | Tracks the source version of value density | Categorical | `V3` | MITRE |
</details>

## Installation
To install and run the project, you can first clone this repository and recreate the dependency environment with the help of the `conda_env.yml` or `requirements.txt` files. You can then run `python src/main.py --help` from the terminal to see how the CLI works to execute the various stages of the pipeline. Keep in mind that running the extraction and preprocessing stages of the pipeline will throw errors without cloning MITRE's entire CVE Project repo (a very large repo with several hundred thousand files) into `data/raw/mitre/cve/`, cloning Nomi-Sec's PoC-in-GitHub repo into `data/raw/exploits/poc/`, and creating a separate dependency environment with a Pip-installed packaged to execute API calls to ExploitDB known as `pyxploitdb`. Also keep in mind that executing any scripts are going to overwrite the previous ones and may corrupt the project's integrity if not handled with care.

### Setting up the Environment

#### For Conda Users
To create a Conda-managed environment (which is how the researchers recommend setting up the project), run:
``` bash
# Create environment
conda env create -f environment.yml

# Activate environment
conda activate cybersecurity-env
```
#### For Pip Users
To create a Venv-managed environment with Pip, run:
``` bash
# Create virtual environment
python -m venv cybersecurity-env

# Activate virtual environment
source cybersecurity-env/bin/activate  # On Windows: cybersecurity-env\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```
## Usage
In general, you can run any given script from the command line with `python src/main.py` followed by intuitive commands like `--extract-cve` (or `-cwe`, `-epss`, `-poc`, etc.), `--preprocess-cve` (or `-cwe`, `-epss`, `nvd`, etc.), and `--compile-data` (which requires cleaned versions of our data sources: `cve_cleaned`, `epss_cleaned`, `nvd_cleaned`, and `exploits_cleaned`). These commands can be issued with flags that change the relative pathways to the files they need to execute, the output destination, and the output file extension (currently limited to Parquet and CSV). These commands are also intuitive: `--cve-input`, `--kev-output`, `--epss-format`, etc.

## Methodology
Pending

## Results
Pending

## License
Pending

## Contact
#### Joseph Brockly-Anderson
<b>Project Analyst</b>
B.A. in Political Science with Minor in Mandarin Chinese, U.C. Davis
Phone: (530) 417-1973
Email: jbrocklyanderson@gmail.com

<!-- ####
<b>Project Administrator</b>

Phone:
Email: