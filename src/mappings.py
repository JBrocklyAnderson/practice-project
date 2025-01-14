'''
This file contains reusable constant mappings designed to help with various
extraction and preprocessing steps.
'''
# § ============================================================================
# § Mappings to extract CVE data
# § ============================================================================
CVE_EXTRACTIONS = {
            'cve_id': ['cveMetadata.cveId'],
            'cve_desc': ['cna.descriptions.value'],
            'cve_state': ['cveMetadata.state'],
            'mitre_cve_res_date': ['cveMetadata.dateReserved'],
            'mitre_cve_publish_date': ['cveMetadata.datePublished'],
            'mitre_cve_public_date': ['containers.cna.datePublic'],
            'cwe_id': ['problemTypes.descriptions.cweId'],
            'cwe_desc': ['cna.problemTypes.descriptions'],
            'vendor': ['cna.affected.vendor'],
            'product': ['cna.affected.product'],
            'prod_status': ['cna.affected.versions.status'],
            'prod_defaultStatus': ['cna.affected.defaultStatus'],
            'prod_version': ['cna.affected.versions.version'],
            'prod_version_type': ['adp.affected.versions.versionType'],
            'prod_lessThan': ['adp.affected.versions.lessThan'],
            'prod_lessThanOrEqual': ['adp.affected.versions.lessThanOrEqual'],
            'solution': ['cna.solutions.value'],
            'cve_discovery': ['cna.source.discovery'],
            'cpe': ['adp.affected.cpes'],
            'cvss_v2': ['cna.metrics.cvssV2_0.baseScore'],
            'cvss_v2_vector': ['cna.metrics.cvssV2_0.vectorString'],
            'cvss_v3': ['cna.metrics.cvssV3_0.baseScore'],
            'cvss_v3_vector': ['cna.metrics.cvssV3_0.vectorString'],
            'cvss_v3_1': ['cna.metrics.cvssV3_1.baseScore'],
            'cvss_v3_1_vector': ['cna.metrics.cvssV3_1.vectorString'],
            'cvss_v4': ['cna.metrics.cvssV4_0.baseScore'],
            'cvss_v4_vector': ['cna.metrics.cvssV4_0.vectorString'],
            'ssvc_exploitation': ['content.options.Exploitation'],
            'ssvc_automatable': ['content.options.Automatable'],
            'ssvc_tech_impact': ['content.options.Technical Impact'],
            'is_kev': ['metrics.other.type']
        }

CONDITIONAL_CVE_EXTRACTIONS = {
    'cve_desc': {
        'paths': ['cna.descriptions'],
        'condition': lambda _, full_data: [
            desc.get('value', '').strip() for desc in full_data
            .get('cna', {}).get('descriptions', [])
            if desc.get('lang', '').strip().lower() in ['en', 'eng', 'english']
        ]
    },
    'cwe_desc': {
        'paths': ['cna.problemTypes.descriptions'],
        'condition': lambda _, full_data: [
            desc.get('description', '') for cwe in full_data
            .get('cna', {}).get('problemTypes', [])
            for desc in cwe.get('descriptions', [])
            if desc.get('lang', '').strip().lower() in ['en', 'eng', 'english']
        ]
    },
    'is_kev': {
        'paths': ['metrics.other.type'],
        'condition': lambda value, _: value == 'kev'
    }
}

# § ============================================================================
# § Mappings to extract CVSS vector features
# § ============================================================================
BASE_CVSS_MAPPINGS = { # Used to reduce code duplication in the other mappings
    'NPC': {'N': 'NONE', 'P': 'PARTIAL', 'C': 'COMPLETE'},
    'N-L-LM-M-MH-H-ND/X': {
        'N': 'NONE',
        'L': 'LOW',
        'M': 'MEDIUM',
        'H': 'HIGH',
        'ND': 'NOT DEFINED',
        'X': 'NOT DEFINED'
    },
    'ND/XUPoCFH': {
        'ND': 'NOT DEFINED',
        'X': 'NOT DEFINED',
        'U': 'UNPROVEN',
        'POC': 'PROOF-OF-CONCEPT',
        'P': 'PROOF-OF-CONCEPT',
        'F': 'FUNCTIONAL',
        'H': 'HIGH'
    },
    'ND/XUWTFOF': {
                'ND': 'NOT DEFINED',
                'X': 'NOT DEFINED',
                'U': 'UNAVAILABLE',
                'W': 'WORKAROUND',
                'TF': 'TEMPORARY FIX',
                'T': 'TEMPORARY FIX',
                'OF': 'OFFICIAL FIX',
                'O': 'OFFICIAL FIX'
            },
    'LANP': {'L': 'LOCAL', 'A': 'ADJACENT', 'N': 'NETWORK', 'P': 'PHYSICAL'},
}

CVSS_BASE_METRICS = {  # For use in extract_cvss_metrics
    'AV': 'attack_vector',
    'AC': 'attack_complexity',
    'PR': 'privileges_required',
    'UI': 'user_interaction',
    'S': 'scope', # Default V3 'scope' overridden in V4
    'C': 'confidentiality',
    'I': 'integrity',
    'A': 'availability',
    'E': 'exploit_maturity',
    'RL': 'remediation_level',
    'RC': 'report_confidence',
    'CR': 'confidentiality_requirement',
    'IR': 'integrity_requirement',
    'AR': 'availability_requirement',
}

CVSS_VERSION_SPECIFIC_METRIC_OVERRIDES = {  # For use in extract_cvss_metrics
    'v2': {
        'Au': 'authentication',
        'CDP': 'collateral_damage_potential',
        'TD': 'target_distribution'
    },
    'v4': {
        'AT': 'attack_requirements',
        'VC': 'vuln_sys_confidentiality',
        'SC': 'sub_sys_confidentiality',
        'VI': 'vuln_sys_integrity',
        'SI': 'sub_sys_integrity',
        'VA': 'vuln_sys_availability',
        'SA': 'sub_sys_availability',
        'S': 'safety',
        'AU': 'automatable',
        'R': 'recovery',
        'V': 'value_density',
        'RE': 'response_effort',
        'U': 'urgency'
    }
}

TOTAL_CVSS_MAPPINGS = { # For use in extract_cvss_metrics
    'v2': {
        'metrics': [
            'AV', 'AC', 'Au', 'C', 'I', 'A', 'E',
            'RL', 'RC', 'CDP', 'TD', 'CR', 'IR', 'AR'
        ],
        'translations': {
            'AV': BASE_CVSS_MAPPINGS['LANP'],
            'AC': BASE_CVSS_MAPPINGS['N-L-LM-M-MH-H-ND/X'], # {'L': 'Low', 'M': 'Medium', 'H': 'High'}
            'Au': {'N': 'NONE', 'S': 'SINGLE', 'M': 'MULTIPLE'},
            'C': BASE_CVSS_MAPPINGS['NPC'],
            'I': BASE_CVSS_MAPPINGS['NPC'],
            'A': BASE_CVSS_MAPPINGS['NPC'],
            'E': BASE_CVSS_MAPPINGS['ND/XUPoCFH'],
            'RL': BASE_CVSS_MAPPINGS['ND/XUWTFOF'],
            'RC': {
                'UC': 'UNCONFIRMED',
                'UR': 'UNCORROBORATED',
                'C': 'CONFIRMED',
                'ND': 'NOT DEFINED'
            },
            'CDP': BASE_CVSS_MAPPINGS['N-L-LM-M-MH-H-ND/X'],
            'TD': BASE_CVSS_MAPPINGS['N-L-LM-M-MH-H-ND/X'],
            'CR': BASE_CVSS_MAPPINGS['N-L-LM-M-MH-H-ND/X'],
            'IR': BASE_CVSS_MAPPINGS['N-L-LM-M-MH-H-ND/X'],
            'AR': BASE_CVSS_MAPPINGS['N-L-LM-M-MH-H-ND/X']
        }
    },
    'v3': {
        'metrics': [
            'AV', 'AC', 'PR', 'UI', 'S', 'C', 'I',
            'A', 'E', 'RL', 'RC', 'CR', 'IR', 'AR'
        ],
        'translations': {
            'AV': BASE_CVSS_MAPPINGS['LANP'],
            'AC': BASE_CVSS_MAPPINGS['N-L-LM-M-MH-H-ND/X'], # * LH
            'PR': BASE_CVSS_MAPPINGS['N-L-LM-M-MH-H-ND/X'], # *
            'UI': {'N': 'NONE', 'R': 'REQUIRED'},
            'S': {'U': 'UNCHANGED', 'C': 'CHANGED'},
            'C': BASE_CVSS_MAPPINGS['N-L-LM-M-MH-H-ND/X'], # *
            'I': BASE_CVSS_MAPPINGS['N-L-LM-M-MH-H-ND/X'], # *
            'A': BASE_CVSS_MAPPINGS['N-L-LM-M-MH-H-ND/X'], # *
            'E': BASE_CVSS_MAPPINGS['ND/XUPoCFH'],
            'RL': BASE_CVSS_MAPPINGS['ND/XUWTFOF'],
            'RC': {
                'X': 'NOT DEFINED',
                'C': 'CONFIRMED',
                'R': 'REASONABLE',
                'U': 'UNKNOWN'},
            'CR': BASE_CVSS_MAPPINGS['N-L-LM-M-MH-H-ND/X'],
            'IR': BASE_CVSS_MAPPINGS['N-L-LM-M-MH-H-ND/X'],
            'AR': BASE_CVSS_MAPPINGS['N-L-LM-M-MH-H-ND/X']
        }
    },
    'v4': {
        'metrics': [
            'AV', 'AC', 'AT', 'PR', 'UI', 'VC', 'SC', 'S', 'AU', 'V', 'U',
            'VI', 'SI', 'VA', 'SA', 'E', 'CR', 'IR', 'AR', 'R', 'RE'
        ],
        'translations': {
            'AV': BASE_CVSS_MAPPINGS['LANP'],
            'AC': BASE_CVSS_MAPPINGS['N-L-LM-M-MH-H-ND/X'], # * LH
            'AT': {'N': 'NONE', 'P': 'PRESENT'},
            'PR': BASE_CVSS_MAPPINGS['N-L-LM-M-MH-H-ND/X'], # *
            'UI': {'N': 'NONE', 'P': 'PASSIVE', 'A': 'ACTIVE'},
            'VC': BASE_CVSS_MAPPINGS['N-L-LM-M-MH-H-ND/X'], # *
            'SC': BASE_CVSS_MAPPINGS['N-L-LM-M-MH-H-ND/X'], # *
            'VI': BASE_CVSS_MAPPINGS['N-L-LM-M-MH-H-ND/X'], # *
            'SI': BASE_CVSS_MAPPINGS['N-L-LM-M-MH-H-ND/X'], # *
            'VA': BASE_CVSS_MAPPINGS['N-L-LM-M-MH-H-ND/X'], # *
            'SA': BASE_CVSS_MAPPINGS['N-L-LM-M-MH-H-ND/X'], # *
            'E': {
                'X': 'NOT DEFINED',
                'A': 'ATTACKED',
                'P': 'PROOF-OF-CONCEPT',
                'U': 'UNREPORTED'
            },
            'CR': BASE_CVSS_MAPPINGS['N-L-LM-M-MH-H-ND/X'],
            'IR': BASE_CVSS_MAPPINGS['N-L-LM-M-MH-H-ND/X'],
            'AR': BASE_CVSS_MAPPINGS['N-L-LM-M-MH-H-ND/X'],
            'S': {'X': 'NOT DEFINED', 'P': 'PRESENT', 'N': 'NEGLIGIBLE'},
            'AU': {'X': 'NOT DEFINED', 'N': 'NO', 'Y': 'YES'},
            'U': {
                'X': 'NOT DEFINED',
                'Red': 'RED',
                'Amber': 'AMBER',
                'Green': 'GREEN',
                'Clear': 'CLEAR'
            },
            'R': {
                'X': 'NOT DEFINED',
                'A': 'AUTOMATIC',
                'U': 'USER',
                'I': 'IRRECOVERABLE'
            },
            'V': {'X': 'NOT DEFINED', 'D': 'DIFFUSE', 'C': 'CONCENTRATED'},
            'RE': BASE_CVSS_MAPPINGS['N-L-LM-M-MH-H-ND/X']
        }
    }
}

CVSS_COL_MAP = { # To be use in compile_cols
    'attack_complexity': [
        'attack_complexity_v2', 'attack_complexity_v3', 'attack_complexity_v4'
    ],
    'attack_requirements': ['attack_requirements_v4'],
    'attack_vector': [
        'attack_vector_v2', 'attack_vector_v3', 'attack_vector_v4'
    ],
    'authentication': ['authentication_v2'],
    'automatable': ['automatable_v4'],
    'availability': [
        'availability_v2', 'availability_v3', 'vuln_sys_availability_v4'
    ],
    'availability_requirement': [
        'availability_requirement_v2',
        'availability_requirement_v3',
        'availability_requirement_v4'
    ],
    'confidentiality': [
        'confidentiality_v2',
        'confidentiality_v3',
        'vuln_sys_confidentiality_v4'
    ],
    'confidentiality_requirement': [
        'confidentiality_requirement_v2',
        'confidentiality_requirement_v3',
        'confidentiality_requirement_v4'
    ],
    'cvss': ['cvss_v2', 'cvss_v3', 'cvss_v4'],
    'exploit_maturity': ['exploit_maturity_v3', 'exploit_maturity_v4'],
    'integrity': ['integrity_v2', 'integrity_v3', 'vuln_sys_integrity_v4'],
    'integrity_requirement': [
        'integrity_requirement_v2',
        'integrity_requirement_v3',
        'integrity_requirement_v4'
    ],
    'privileges_required': ['privileges_required_v3', 'privileges_required_v4'],
    'recovery': ['recovery_v4'],
    'remediation_level': ['remediation_level_v3'],
    'report_confidence': ['report_confidence_v3', ],
    'response_effort': ['response_effort_v4'],
    'safety': ['safety_v4'],
    'scope': ['scope_v3'],
    'sub_sys_availability': ['sub_sys_availability_v4'],
    'sub_sys_confidentiality': ['sub_sys_confidentiality_v4'],
    'sub_sys_integrity': ['sub_sys_integrity_v4'],
    'urgency': ['urgency_v4'],
    'user_interaction': ['user_interaction_v3', 'user_interaction_v4'],
    'value_density': ['value_density_v4']
}