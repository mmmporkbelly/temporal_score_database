"""
Populate the temporal vector
"""

import numpy as np
import logging
from .calculate_temporal import calculate_temporal, calculate_base_severity


def populate_temporal(dataframe):
    df = dataframe

    # df[['NVD_baseSeverity', 'Mitre_baseSeverity']] = df[['NVD_baseSeverity', 'Mitre_baseSeverity']].replace(
    #     to_replace=['NONE', 'nan', 'NaN'],
    #     value='',
    #     inplace=True
    # )

    # Edit df first to figure out which vector to use. NVD vectors will always be used if available
    df["cvss_vector_used"] = df["NVD_vectorString"].fillna(df["Mitre_vectorString"])
    df["cvss_version_used"] = df["NVD_version"].fillna(df["Mitre_version"])
    df["cvss_report_confidence"] = df["NVD_Vulnerability_Status"].fillna(df["Mitre_Report_State"])
    df["cvss_has_reference"] = df["NVD_has_reference"].fillna(df["Mitre_References"])

    # Set up conditions. Note: Tilde (~) indicates is not, or ! in some languages
    # Condition for two or more POCs
    condition_two_poc = (
        (df['on_kev'] & df['On_Nuclei']) |
        (df['on_kev'] & df['POC_In_Github']) |
        (df['on_kev'] & df['In_ExploitDB']) |
        (df['On_Nuclei'] & df['POC_In_Github']) |
        (df['On_Nuclei'] & df['In_ExploitDB']) |
        (df['POC_In_Github'] & df['In_ExploitDB'])
    )

    # Condition for one POC
    condition_one_poc = (
        df['on_kev'] |
        df['On_Nuclei'] |
        df['POC_In_Github'] |
        df['In_ExploitDB']
    )

    # Condition for 'E:H'
    condition_eh = (
            (condition_two_poc & df['Metasploit_Module']) |
            (condition_two_poc & df['affiliatedwithransomware']) |
            (df['Metasploit_Module'] & df['affiliatedwithransomware'])
    )

    # Condition for 'E:F'
    condition_ef = (
        ~condition_eh & (
            condition_two_poc |
            df['Metasploit_Module'] |
            df['affiliatedwithransomware']
        )
    )
    # Condition for 'E:P'
    condition_ep = (~condition_eh) & (~condition_ef) & condition_one_poc

    # Condition for 'E:U'
    condition_eu = (~condition_eh) & (~condition_ef) & (~condition_one_poc)

    # Conditions for Report Confidence. Only applicable to v2 and v3
    condition_rc_u = (df['cvss_report_confidence'] == 'REJECTED')
    condition_rc_r = ((df['cvss_report_confidence'] == 'Awaiting Analysis') |
                      (df['cvss_report_confidence'] == 'Undergoing Analysis') |
                      (df['cvss_report_confidence'] == 'Received')
                      )
    condition_rc_c = (~condition_rc_u & ~condition_rc_r)

    # Condition for patch level. If it has a reference, we can assume there is some sort of workaround.
    condition_rl_c = (df['NVD_Patch'] == True)
    condition_rl_w = (~condition_rl_c & (df['cvss_has_reference'].notna()))

    # Populate Temporal Vector
    logging.info("Populating temporal vectors...")

    # All V2 conditions
    # Maturity: High
    condition_cvss_v2 = ((df['cvss_version_used'].astype(str) == '2') | (df['cvss_version_used'].astype(str) == '2.0'))
    df.loc[condition_cvss_v2 & condition_eh & condition_rc_c & condition_rl_c, 'exploit_maturity'] = 'E:H/RL:OF/RC:C'
    df.loc[condition_cvss_v2 & condition_eh & condition_rc_r & condition_rl_c, 'exploit_maturity'] = 'E:H/RL:OF/RC:UR'
    df.loc[condition_cvss_v2 & condition_eh & condition_rc_u & condition_rl_c, 'exploit_maturity'] = 'E:H/RL:OF/RC:UC'
    df.loc[condition_cvss_v2 & condition_eh & condition_rc_c & condition_rl_w, 'exploit_maturity'] = 'E:H/RL:TF/RC:C'
    df.loc[condition_cvss_v2 & condition_eh & condition_rc_r & condition_rl_w, 'exploit_maturity'] = 'E:H/RL:TF/RC:UR'
    df.loc[condition_cvss_v2 & condition_eh & condition_rc_u & condition_rl_w, 'exploit_maturity'] = 'E:H/RL:TF/RC:UC'
    df.loc[condition_cvss_v2 & condition_eh & condition_rc_c & ~condition_rl_w, 'exploit_maturity'] = 'E:H/RL:U/RC:C'
    df.loc[condition_cvss_v2 & condition_eh & condition_rc_r & ~condition_rl_w, 'exploit_maturity'] = 'E:H/RL:U/RC:UR'
    df.loc[condition_cvss_v2 & condition_eh & condition_rc_u & ~condition_rl_w, 'exploit_maturity'] = 'E:H/RL:U/RC:UC'

    # Maturity: Functional
    df.loc[condition_cvss_v2 & condition_ef & condition_rc_c & condition_rl_c, 'exploit_maturity'] = 'E:F/RL:OF/RC:C'
    df.loc[condition_cvss_v2 & condition_ef & condition_rc_r & condition_rl_c, 'exploit_maturity'] = 'E:F/RL:OF/RC:UR'
    df.loc[condition_cvss_v2 & condition_ef & condition_rc_u & condition_rl_c, 'exploit_maturity'] = 'E:F/RL:OF/RC:UC'
    df.loc[condition_cvss_v2 & condition_ef & condition_rc_c & condition_rl_w, 'exploit_maturity'] = 'E:F/RL:TF/RC:C'
    df.loc[condition_cvss_v2 & condition_ef & condition_rc_r & condition_rl_w, 'exploit_maturity'] = 'E:F/RL:TF/RC:UR'
    df.loc[condition_cvss_v2 & condition_ef & condition_rc_u & condition_rl_w, 'exploit_maturity'] = 'E:F/RL:TF/RC:UC'
    df.loc[condition_cvss_v2 & condition_ef & condition_rc_c & ~condition_rl_w, 'exploit_maturity'] = 'E:F/RL:U/RC:C'
    df.loc[condition_cvss_v2 & condition_ef & condition_rc_r & ~condition_rl_w, 'exploit_maturity'] = 'E:F/RL:U/RC:UR'
    df.loc[condition_cvss_v2 & condition_ef & condition_rc_u & ~condition_rl_w, 'exploit_maturity'] = 'E:F/RL:U/RC:UC'

    # Maturity: POC
    df.loc[condition_cvss_v2 & condition_ep & condition_rc_c & condition_rl_c, 'exploit_maturity'] = 'E:POC/RL:OF/RC:C'
    df.loc[condition_cvss_v2 & condition_ep & condition_rc_r & condition_rl_c, 'exploit_maturity'] = 'E:POC/RL:OF/RC:UR'
    df.loc[condition_cvss_v2 & condition_ep & condition_rc_u & condition_rl_c, 'exploit_maturity'] = 'E:POC/RL:OF/RC:UC'
    df.loc[condition_cvss_v2 & condition_ep & condition_rc_c & condition_rl_w, 'exploit_maturity'] = 'E:POC/RL:TF/RC:C'
    df.loc[condition_cvss_v2 & condition_ep & condition_rc_r & condition_rl_w, 'exploit_maturity'] = 'E:POC/RL:TF/RC:UR'
    df.loc[condition_cvss_v2 & condition_ep & condition_rc_u & condition_rl_w, 'exploit_maturity'] = 'E:POC/RL:TF/RC:UC'
    df.loc[condition_cvss_v2 & condition_ep & condition_rc_c & ~condition_rl_w, 'exploit_maturity'] = 'E:POC/RL:U/RC:C'
    df.loc[condition_cvss_v2 & condition_ep & condition_rc_r & ~condition_rl_w, 'exploit_maturity'] = 'E:POC/RL:U/RC:UR'
    df.loc[condition_cvss_v2 & condition_ep & condition_rc_u & ~condition_rl_w, 'exploit_maturity'] = 'E:POC/RL:U/RC:UC'

    # Maturity: Unproven
    df.loc[condition_cvss_v2 & condition_eu & condition_rc_c & condition_rl_c, 'exploit_maturity'] = 'E:U/RL:OF/RC:C'
    df.loc[condition_cvss_v2 & condition_eu & condition_rc_r & condition_rl_c, 'exploit_maturity'] = 'E:U/RL:OF/RC:UR'
    df.loc[condition_cvss_v2 & condition_eu & condition_rc_u & condition_rl_c, 'exploit_maturity'] = 'E:U/RL:OF/RC:UC'
    df.loc[condition_cvss_v2 & condition_eu & condition_rc_c & condition_rl_w, 'exploit_maturity'] = 'E:U/RL:TF/RC:C'
    df.loc[condition_cvss_v2 & condition_eu & condition_rc_r & condition_rl_w, 'exploit_maturity'] = 'E:U/RL:TF/RC:UR'
    df.loc[condition_cvss_v2 & condition_eu & condition_rc_u & condition_rl_w, 'exploit_maturity'] = 'E:U/RL:TF/RC:UC'
    df.loc[condition_cvss_v2 & condition_eu & condition_rc_c & ~condition_rl_w, 'exploit_maturity'] = 'E:U/RL:U/RC:C'
    df.loc[condition_cvss_v2 & condition_eu & condition_rc_r & ~condition_rl_w, 'exploit_maturity'] = 'E:U/RL:U/RC:UR'
    df.loc[condition_cvss_v2 & condition_eu & condition_rc_u & ~condition_rl_w, 'exploit_maturity'] = 'E:U/RL:U/RC:UC'

    # All V3 and V3.1 conditions. Make conditional for cvss version used
    # Maturity: High
    condition_cvss_v3 = ((df['cvss_version_used'].astype(str) == '3.0') | (df['cvss_version_used'].astype(str) == '3.1') | (df['cvss_version_used'].astype(str) == '3'))
    df.loc[condition_cvss_v3 & condition_eh & condition_rc_c & condition_rl_c, 'exploit_maturity'] = 'E:H/RL:O/RC:C'
    df.loc[condition_cvss_v3 & condition_eh & condition_rc_r & condition_rl_c, 'exploit_maturity'] = 'E:H/RL:O/RC:R'
    df.loc[condition_cvss_v3 & condition_eh & condition_rc_u & condition_rl_c, 'exploit_maturity'] = 'E:H/RL:O/RC:U'
    df.loc[condition_cvss_v3 & condition_eh & condition_rc_c & condition_rl_w, 'exploit_maturity'] = 'E:H/RL:T/RC:C'
    df.loc[condition_cvss_v3 & condition_eh & condition_rc_r & condition_rl_w, 'exploit_maturity'] = 'E:H/RL:T/RC:R'
    df.loc[condition_cvss_v3 & condition_eh & condition_rc_u & condition_rl_w, 'exploit_maturity'] = 'E:H/RL:T/RC:U'
    df.loc[condition_cvss_v3 & condition_eh & condition_rc_c & ~condition_rl_w, 'exploit_maturity'] = 'E:H/RL:U/RC:C'
    df.loc[condition_cvss_v3 & condition_eh & condition_rc_r & ~condition_rl_w, 'exploit_maturity'] = 'E:H/RL:U/RC:R'
    df.loc[condition_cvss_v3 & condition_eh & condition_rc_u & ~condition_rl_w, 'exploit_maturity'] = 'E:H/RL:U/RC:U'

    # Maturity: Functional
    df.loc[condition_cvss_v3 & condition_ef & condition_rc_c & condition_rl_c, 'exploit_maturity'] = 'E:F/RL:O/RC:C'
    df.loc[condition_cvss_v3 & condition_ef & condition_rc_r & condition_rl_c, 'exploit_maturity'] = 'E:F/RL:O/RC:R'
    df.loc[condition_cvss_v3 & condition_ef & condition_rc_u & condition_rl_c, 'exploit_maturity'] = 'E:F/RL:O/RC:U'
    df.loc[condition_cvss_v3 & condition_ef & condition_rc_c & condition_rl_w, 'exploit_maturity'] = 'E:F/RL:T/RC:C'
    df.loc[condition_cvss_v3 & condition_ef & condition_rc_r & condition_rl_w, 'exploit_maturity'] = 'E:F/RL:T/RC:R'
    df.loc[condition_cvss_v3 & condition_ef & condition_rc_u & condition_rl_w, 'exploit_maturity'] = 'E:F/RL:T/RC:U'
    df.loc[condition_cvss_v3 & condition_ef & condition_rc_c & ~condition_rl_w, 'exploit_maturity'] = 'E:F/RL:U/RC:C'
    df.loc[condition_cvss_v3 & condition_ef & condition_rc_r & ~condition_rl_w, 'exploit_maturity'] = 'E:F/RL:U/RC:R'
    df.loc[condition_cvss_v3 & condition_ef & condition_rc_u & ~condition_rl_w, 'exploit_maturity'] = 'E:F/RL:U/RC:U'

    # Maturity: POC
    df.loc[condition_cvss_v3 & condition_ep & condition_rc_c & condition_rl_c, 'exploit_maturity'] = 'E:P/RL:O/RC:C'
    df.loc[condition_cvss_v3 & condition_ep & condition_rc_r & condition_rl_c, 'exploit_maturity'] = 'E:P/RL:O/RC:R'
    df.loc[condition_cvss_v3 & condition_ep & condition_rc_u & condition_rl_c, 'exploit_maturity'] = 'E:P/RL:O/RC:U'
    df.loc[condition_cvss_v3 & condition_ep & condition_rc_c & condition_rl_w, 'exploit_maturity'] = 'E:P/RL:T/RC:C'
    df.loc[condition_cvss_v3 & condition_ep & condition_rc_r & condition_rl_w, 'exploit_maturity'] = 'E:P/RL:T/RC:R'
    df.loc[condition_cvss_v3 & condition_ep & condition_rc_u & condition_rl_w, 'exploit_maturity'] = 'E:P/RL:T/RC:U'
    df.loc[condition_cvss_v3 & condition_ep & condition_rc_c & ~condition_rl_w, 'exploit_maturity'] = 'E:P/RL:U/RC:C'
    df.loc[condition_cvss_v3 & condition_ep & condition_rc_r & ~condition_rl_w, 'exploit_maturity'] = 'E:P/RL:U/RC:R'
    df.loc[condition_cvss_v3 & condition_ep & condition_rc_u & ~condition_rl_w, 'exploit_maturity'] = 'E:P/RL:U/RC:U'

    # Maturity: Unproven
    df.loc[condition_cvss_v3 & condition_eu & condition_rc_c & condition_rl_c, 'exploit_maturity'] = 'E:U/RL:O/RC:C'
    df.loc[condition_cvss_v3 & condition_eu & condition_rc_r & condition_rl_c, 'exploit_maturity'] = 'E:U/RL:O/RC:R'
    df.loc[condition_cvss_v3 & condition_eu & condition_rc_u & condition_rl_c, 'exploit_maturity'] = 'E:U/RL:O/RC:U'
    df.loc[condition_cvss_v3 & condition_eu & condition_rc_c & condition_rl_w, 'exploit_maturity'] = 'E:U/RL:T/RC:C'
    df.loc[condition_cvss_v3 & condition_eu & condition_rc_r & condition_rl_w, 'exploit_maturity'] = 'E:U/RL:T/RC:R'
    df.loc[condition_cvss_v3 & condition_eu & condition_rc_u & condition_rl_w, 'exploit_maturity'] = 'E:U/RL:T/RC:U'
    df.loc[condition_cvss_v3 & condition_eu & condition_rc_c & ~condition_rl_w, 'exploit_maturity'] = 'E:U/RL:U/RC:C'
    df.loc[condition_cvss_v3 & condition_eu & condition_rc_r & ~condition_rl_w, 'exploit_maturity'] = 'E:U/RL:U/RC:R'
    df.loc[condition_cvss_v3 & condition_eu & condition_rc_u & ~condition_rl_w, 'exploit_maturity'] = 'E:U/RL:U/RC:U'

    # All v4 conditions. v4 only supports exploit code maturity
    condition_cvss_v4 = ((df['cvss_version_used'].astype(str) == '4') | (df['cvss_version_used'].astype(str) == '4.0'))
    df.loc[condition_cvss_v4 & condition_eh, 'exploit_maturity'] = 'E:A'
    df.loc[condition_cvss_v4 & condition_ef, 'exploit_maturity'] = 'E:A'
    df.loc[condition_cvss_v4 & condition_ep, 'exploit_maturity'] = 'E:P'
    df.loc[condition_cvss_v4 & condition_eu, 'exploit_maturity'] = 'E:U'

    # Update vector with exploit maturity
    df['temporal_vector'] = np.where(df['cvss_vector_used'], df['cvss_vector_used'] + '/' + df['exploit_maturity'], False)

    # Extracting CVSS scores and severities
    logging.info('Computing temporal scores and severities')
    df[['temporal_score', 'temporal_severity']] = df.apply(calculate_temporal, axis=1, result_type='expand')
    df["cvss_base_severity"] = df.apply(calculate_base_severity, axis=1)

    # Give breakdown of severity change
    logging.info("Here is the breakdown of what has changed")
    logging.info(df.value_counts('cvss_base_severity'))
    logging.info(df.value_counts('temporal_severity'))

    # Write to excel
    return df
