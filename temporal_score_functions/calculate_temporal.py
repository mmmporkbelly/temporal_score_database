"""
Calculate the temporal score of a vulnerability using the CVSS library
"""
import logging
from cvss import CVSS2, CVSS3, CVSS4


def calculate_temporal(row):
    try:
        logging.info(f"Calculating {row['CVE_ID']} Temporal Scores")
        if '4' in str(row['cvss_version_used']):
            c = CVSS4(row['temporal_vector'])
            return c.vector, str(c.severities()[1]).upper()
        elif '3' in str(row['cvss_version_used']):
            c = CVSS3(row['temporal_vector'])
            return c.temporal_score, str(c.severities()[1]).upper()
        elif '2' in str(row['cvss_version_used']):
            c = CVSS2(row['temporal_vector'])
            severity = str(c.severities()[1]).upper()
            return c.temporal_score, severity
        return False, False
    except Exception as e:
        logging.error(f"{e}: Unable to calculate temporal scores for {row['CVE_ID']}")
        return False, False


# This function is for calculating base severity. Necessary to fill out dataframe
def calculate_base_severity(row):
    try:
        logging.info(f"Calculating {row['CVE_ID']} Base Severity")
        if '4' in str(row['cvss_version_used']):
            c = CVSS4(row['cvss_vector_used'])
            return str(c.severity).upper()
        elif '3' in str(row['cvss_version_used']):
            c = CVSS3(row['cvss_vector_used'])
            return str(c.severities()[0]).upper()
        elif '2' in str(row['cvss_version_used']):
            c = CVSS2(row['cvss_vector_used'])
            return str(c.severities()[0]).upper()
        return False
    except Exception as e:
        logging.error(f"{e}: Unable to calculate base severity for {row['CVE_ID']}")
        return False
