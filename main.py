"""
Main file for running and consolidating all data.
"""

import pandas as pd
import os
import logging
from datetime import date
from exploit_df_functions import *
from nvd_functions import *
from mitre_functions import *
from temporal_score_functions import *
from aws_functions import *


def main():
    # Configure logging, make sure log folder exists
    log_path = 'Logs/'
    if not os.path.exists(log_path):
        os.makedirs(log_path)
    log_file_path = log_path + f'{date.today()}.log'
    logging.basicConfig(filename=log_file_path, level=logging.DEBUG,
                        format='%(asctime)s - %(levelname)s - %(message)s')
    logging.getLogger().addHandler(logging.StreamHandler())

    # Download NVD files
    download_bucket_files.download_nvd_file()

    """
    First process the MITRE file
    """

    logging.info("Creating MITRE File...")
    # Download mitre files
    logging.info("Downloading all MITRE files...")
    download_mitre.download_mitre_file()

    # Combine mitre json files
    logging.info("Combing all MITRE json files...")
    mitre_raw_json_files = 'Downloads/MitreCVE/cves'
    mitre_json_files = 'ProcessedFiles/Mitre CVE Json Year/'
    combine_json.combine_json_files_by_year(mitre_raw_json_files, mitre_json_files)

    # Process json files
    logging.info("Validating MITRE json files...")
    validate_json.parse_json_files(mitre_json_files)

    # Convert json to csv
    logging.info("Combining all json files into one dataframe...")
    mitre_df = merge_mitre_to_df.process_all_files()

    """
    Then process the NVD dataframe and combine the two
    """

    # Instantiate NVD DF class
    logging.info("Starting NVD file retrieval...")
    nvd_df_object = nvd_dataframe.NVDDataFrame()
    nvd_df = nvd_df_object.all_df_data()

    # Combine dataframes
    logging.info("Combining Dataframes...")

    # Merge the data on CVE ID with full outer join
    merged_data = pd.merge(nvd_df, mitre_df, left_on='NVD_CVE_ID', right_on='Mitre_CVE_ID',
                           how='outer')

    # Determine where the data is missing and create a new column 'CVE Trueup_Missing'
    merged_data['CVE_TrueUp_Missing'] = merged_data.apply(
        lambda row: 'MITRE' if pd.isnull(row['Mitre_CVE_ID']) else ('NVD' if pd.isnull(row['NVD_CVE_ID']) else ''),
        axis=1)

    # Now create a CVE_ID column, and remove NVD_CVE_ID and MITRE_CVE_ID columns
    merged_data["CVE_ID"] = merged_data["NVD_CVE_ID"].fillna(merged_data["Mitre_CVE_ID"])
    merged_data = merged_data.drop(columns=['NVD_CVE_ID', 'Mitre_CVE_ID'])

    # Put CVE_ID as first row
    col = merged_data.pop("CVE_ID")
    merged_data.insert(0, col.name, col)

    # Drop duplicates just in case
    merged_data.drop_duplicates(subset=['CVE_ID'], keep='first', inplace=True)

    """
    Now add all the Exploit Data
    """

    # Add all the KEV Data
    kev_df_object = exploit_dataframe_classes.KevDataFrame()
    kev_df = kev_df_object.all_df_data()
    merged_data = pd.merge(merged_data, kev_df, how='outer', on='CVE_ID')

    # Add all the EPSS Data
    epss_df_object = exploit_dataframe_classes.EPSSDataFrame()
    epss_df = epss_df_object.all_df_data()
    merged_data = pd.merge(merged_data, epss_df, left_on='CVE_ID', right_on='CVE_ID', how='outer')

    # Add all the Exploitdb Data
    exploitdb_df_object = exploit_dataframe_classes.ExploitDBDataFrame()
    exploitdb_df = exploitdb_df_object.all_df_data()
    merged_data = pd.merge(merged_data, exploitdb_df, on='CVE_ID', how='outer')

    # Add all the Metasploit data
    metasploit_df_object = exploit_dataframe_classes.MetasploitDataFrame()
    metasploit_df = metasploit_df_object.all_df_data()
    merged_data = pd.merge(merged_data, metasploit_df, on='CVE_ID', how='outer')

    # Add all the Github POC data
    github_df_object = exploit_dataframe_classes.GithubDataFrame()
    github_df = github_df_object.all_df_data()
    merged_data = pd.merge(merged_data, github_df, on='CVE_ID', how='outer')

    # Add all the Nuclei POC data
    nuclei_df_object = exploit_dataframe_classes.NucleiDataFrame()
    nuclei_df = nuclei_df_object.all_df_data()
    merged_data = pd.merge(merged_data, nuclei_df, on='CVE_ID', how='outer')

    """
    Calculate Temporal Scores
    """

    # Add all temporal vectors
    final_df = add_temporal_vector.populate_temporal(merged_data)

    # Again, drop all duplicates just in case
    final_df.drop_duplicates(subset=['CVE_ID'], keep='first', inplace=True)

    # Save the merged data to a new xlsx file
    with pd.ExcelWriter(
            f'ProcessedFiles/final_result_{date.today()}.xlsx',
            engine="xlsxwriter",
            engine_kwargs={'options': {'strings_to_formulas': False, 'strings_to_urls': False}}
    ) as writer:
        final_df.to_excel(writer, index=False)

    # Upload to AWS
    upload_to_bucket.upload_all_files(log_file_path)


if __name__ == '__main__':
    main()
