import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random

# Set random seed for reproducibility
np.random.seed(42)
random.seed(42)

# Define helper functions
def generate_cvss_score(severity):
    if severity == 'Low':
        return round(np.random.uniform(2.0, 3.9), 1)
    elif severity == 'Medium':
        return round(np.random.uniform(4.0, 6.9), 1)
    elif severity == 'High':
        return round(np.random.uniform(7.0, 8.9), 1)
    else:  # Critical
        return round(np.random.uniform(9.0, 10.0), 1)

def generate_time_to_patch(severity):
    if severity == 'Critical':
        return int(np.random.uniform(150, 180))
    elif severity == 'High':
        return int(np.random.uniform(180, 270))
    elif severity == 'Medium':
        return int(np.random.uniform(270, 365))
    else:  # Low
        return int(np.random.uniform(365, 450))

def generate_epss_score(cvss_score, exploited):
    base_prob = (cvss_score / 10) * 0.3
    if exploited == 1:
        return round(np.random.uniform(0.3, 0.819), 3)
    else:
        return round(np.random.uniform(0.01, base_prob), 3)

# Create 1000 records with validated distributions
severity_distribution = {
    'Low': 150,     # 15%
    'Medium': 300,  # 30%
    'High': 400,    # 40%
    'Critical': 150 # 15%
}

# Industry types and risk levels
industry_sectors = [
    {'name': 'Power Generation', 'risk': 5},
    {'name': 'Power Transmission', 'risk': 5},
    {'name': 'Energy Distribution', 'risk': 4},
    {'name': 'Water Treatment', 'risk': 4},
    {'name': 'Oil and Gas', 'risk': 5},
    {'name': 'Manufacturing', 'risk': 3},
    {'name': 'Chemical Processing', 'risk': 4},
    {'name': 'Transportation', 'risk': 3},
    {'name': 'Building Automation', 'risk': 2}
]

# Device types
device_types = [
    'PLC', 'RTU', 'HMI', 'IED', 'Smart Meter', 'SCADA Gateway',
    'Historian Server', 'Protocol Converter', 'Engineering Workstation'
]

# Generate records
records = []
record_index = 0

for severity, count in severity_distribution.items():
    for i in range(count):
        cvss_score = generate_cvss_score(severity)

        # Calculate exploitation probability
        base_exploit_prob = (cvss_score / 10) ** 2
        severity_mult = {
            'Critical': 1.5,
            'High': 1.2,
            'Medium': 0.8,
            'Low': 0.5
        }[severity]

        # Target ~7% overall exploitation rate with distribution based on severity
        exploited = 1 if np.random.random() < (base_exploit_prob * severity_mult * 0.07) else 0

        # Generate core metrics
        device_criticality = np.random.randint(1, 6)  # 1-5

        # Adjust device criticality based on CVSS (higher CVSS more likely to have higher criticality)
        device_criticality_adjusted = min(5, max(1,
            int(device_criticality * 0.7 + (cvss_score / 10) * 5 * 0.3)))

        # SCADA/IIoT specific metrics
        iiot_integration_level = np.random.randint(0, 4)  # 0-3
        legacy_system_dependency = np.random.randint(0, 5)  # 0-4
        component_interconnection_score = np.random.randint(1, 6)  # 1-5
        system_complexity = np.random.randint(1, 6)  # 1-5

        # Impact metrics based on device criticality and CVSS
        operational_impact_score = min(5, max(0,
            int((device_criticality_adjusted * 0.6) + (cvss_score / 10 * 5 * 0.4))))
        physical_impact_potential = min(4, max(0,
            int((device_criticality_adjusted * 0.7) + (np.random.random() * 0.3 * 4))))
        financial_impact_score = np.random.randint(1, 6)  # 1-5
        regulatory_impact_score = np.random.randint(0, 4)  # 0-3
        cascade_effect_score = min(5, max(0,
            int((device_criticality_adjusted * 0.5) + (system_complexity * 0.5))))

        # Exploitation metrics
        days_until_first_exploit = np.random.randint(1, 181) if exploited else 0
        exploit_success_rate = round(np.random.uniform(0.3, 1.0), 3) if exploited else round(np.random.uniform(0, 0.3), 3)
        nation_state_threat_level = min(3, max(0,
            int((device_criticality_adjusted / 5 * 3) + (np.random.random() * 0.3 * 3))))
        supply_chain_risk_score = np.random.randint(0, 5)  # 0-4
        attack_complexity = np.random.randint(1, 6)  # 1-5

        # Patch management metrics
        time_to_patch_release = generate_time_to_patch(severity)
        patch_implementation_complexity = np.random.randint(1, 6)  # 1-5
        system_recovery_time = np.random.randint(1, 169)  # 1-168 hours
        patch_testing_impact = np.random.randint(0, 5)  # 0-4
        deployment_risk = np.random.randint(1, 6)  # 1-5

        # Detection and mitigation metrics
        detection_complexity_score = np.random.randint(1, 6)  # 1-5
        mitigation_effectiveness = round(np.random.random(), 3)  # 0-1
        alert_generation_rate = np.random.randint(0, 101)  # 0-100
        false_positive_rate = round(np.random.random() * 0.5, 3)  # 0-0.5
        response_time_required = np.random.randint(1, 25)  # 1-24 hours

        # Environmental context
        selected_industry = random.choice(industry_sectors)
        industry_sector = selected_industry['name']
        industry_sector_risk = selected_industry['risk']
        geographic_impact_scope = np.random.randint(1, 5)  # 1-4
        operational_technology_impact = np.random.randint(0, 6)  # 0-5
        network_segmentation_level = np.random.randint(0, 4)  # 0-3
        access_control_level = np.random.randint(1, 5)  # 1-4

        # Technical complexity metrics
        attack_vector_complexity = np.random.randint(1, 6)  # 1-5
        attack_chain_length = np.random.randint(1, 11)  # 1-10
        required_access_level = np.random.randint(0, 4)  # 0-3
        authentication_requirements = np.random.randint(0, 4)  # 0-3

        # Random dates for the CVE
        year = random.choice([2023, 2024])
        month = np.random.randint(1, 13)
        day = np.random.randint(1, 29)
        published_date = f"{year}-{month:02d}-{day:02d}"

        # Generate EPSS score
        epss_score = generate_epss_score(cvss_score, exploited)

        # Calculate SECUREGRID score
        securegrid_score = round(
            (10 * device_criticality_adjusted) +
            (7 * operational_impact_score) +
            (5 * nation_state_threat_level) +
            (4 * attack_complexity) +
            (3 * supply_chain_risk_score) +
            (3 * system_complexity) +
            (2 * iiot_integration_level) +
            (0.5 * cvss_score), 2)

        # Create record with all 40 variables
        record = {
            # Core Vulnerability Metrics
            "CVE_ID": f"CVE-{year}-{1000 + record_index}",
            "CVE_Published_Date": published_date,
            "CVSS_Score": cvss_score,
            "EPSS_Score": epss_score,
            "Exploitability_Score": round(np.random.random() * 10, 2),

            # SCADA/IIoT Specific Metrics
            "Device_Criticality": device_criticality_adjusted,
            "IIoT_Integration_Level": iiot_integration_level,
            "Legacy_System_Dependency": legacy_system_dependency,
            "Component_Interconnection_Score": component_interconnection_score,
            "System_Complexity": system_complexity,

            # Impact Metrics
            "Operational_Impact_Score": operational_impact_score,
            "Physical_Impact_Potential": physical_impact_potential,
            "Financial_Impact_Score": financial_impact_score,
            "Regulatory_Impact_Score": regulatory_impact_score,
            "Cascade_Effect_Score": cascade_effect_score,

            # Exploitation Metrics
            "Days_Until_First_Exploit": days_until_first_exploit,
            "Exploit_Success_Rate": exploit_success_rate,
            "Nation_State_Threat_Level": nation_state_threat_level,
            "Supply_Chain_Risk_Score": supply_chain_risk_score,
            "Attack_Complexity": attack_complexity,

            # Patch Management Metrics
            "Time_To_Patch_Release": time_to_patch_release,
            "Patch_Implementation_Complexity": patch_implementation_complexity,
            "System_Recovery_Time": system_recovery_time,
            "Patch_Testing_Impact": patch_testing_impact,
            "Deployment_Risk": deployment_risk,

            # Detection and Mitigation Metrics
            "Detection_Complexity_Score": detection_complexity_score,
            "Mitigation_Effectiveness": mitigation_effectiveness,
            "Alert_Generation_Rate": alert_generation_rate,
            "False_Positive_Rate": false_positive_rate,
            "Response_Time_Required": response_time_required,

            # Environmental Context
            "Industry_Sector": industry_sector,
            "Industry_Sector_Risk": industry_sector_risk,
            "Geographic_Impact_Scope": geographic_impact_scope,
            "Operational_Technology_Impact": operational_technology_impact,
            "Network_Segmentation_Level": network_segmentation_level,
            "Access_Control_Level": access_control_level,

            # Technical Complexity Metrics
            "Attack_Vector_Complexity": attack_vector_complexity,
            "Attack_Chain_Length": attack_chain_length,
            "Required_Access_Level": required_access_level,
            "Authentication_Requirements": authentication_requirements,

            # Target variable and final score
            "Exploited": exploited,
            "SECUREGRID_Score": securegrid_score
        }

        records.append(record)
        record_index += 1

# Create DataFrame
df = pd.DataFrame(records)

# Validate dataset
print(f"Total records: {len(df)}")
print("\nCVSS Distribution:")
cvss_bins = [0, 4.0, 7.0, 9.0, 10.0]
cvss_labels = ['Low (0-3.9)', 'Medium (4.0-6.9)', 'High (7.0-8.9)', 'Critical (9.0-10.0)']
cvss_counts = pd.cut(df['CVSS_Score'], bins=cvss_bins, labels=cvss_labels).value_counts().sort_index()
for severity, count in cvss_counts.items():
    print(f"{severity}: {count} ({count/len(df)*100:.2f}%)")

print("\nExploitation Rate:")
print(f"Exploited: {df['Exploited'].sum()} ({df['Exploited'].mean()*100:.2f}%)")

# Check correlations
print("\nKey Correlations:")
cvss_exploit_corr = df['CVSS_Score'].corr(df['Exploited'])
epss_exploit_corr = df['EPSS_Score'].corr(df['Exploited'])
device_crit_exploit_corr = df['Device_Criticality'].corr(df['Exploited'])
securegrid_exploit_corr = df['SECUREGRID_Score'].corr(df['Exploited'])

print(f"CVSS vs Exploitation: r = {cvss_exploit_corr:.3f}")
print(f"EPSS vs Exploitation: r = {epss_exploit_corr:.3f}")
print(f"Device Criticality vs Exploitation: r = {device_crit_exploit_corr:.3f}")
print(f"SECUREGRID vs Exploitation: r = {securegrid_exploit_corr:.3f}")

# Save to CSV (uncomment to save)
df.to_csv('SCADA_Dataset_1000_CVEs_40_Variables.csv', index=False)
print("\nDataset saved to 'SCADA_Dataset_1000_CVEs_40_Variables.csv'")