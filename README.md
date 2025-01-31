# Patch Prioritization Analysis
<span style='font-weight:900;color:#ff9900;text-shadow:0 0 5px #ffff00;'>PENDING README</span>

The last time MITRE's CVE Project filebase was pulled into the local repository
from which this project extracts crucial CVE data was Wednesday, December 11,
2024 at 04:40:57.

## Data Sources
### MITRE
#### CVE


#### CWE


### NVD


### FIRST


### Exploit DB


### Setting up the environment
#### For Conda users
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


- Patch Release Date
- Exploit Code Date (1st observed date)
- MITRE CVE listing date for CVE ✅
- EPSS (on proof of concept date)
- CVSS (use version 3.0 and 3.1 but for the missing ones, use other versions but flag them and the version numbers for tracking) ✅
- CVSS (various metrics) ✅
- Number of exploit codes available for the CVE