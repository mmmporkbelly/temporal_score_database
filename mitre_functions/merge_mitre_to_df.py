"""
The following functions are for converting JSON files containing CVE data into structured CSV files.
It automates the extraction of relevant CVE information and CVSS metrics,
and compiles them into a format suitable for further analysis or reporting.
Note: Will throw error if xlsx writer is not used.
"""

import pandas as pd
import json
import os
import glob
import logging
import xlsxwriter
from datetime import date


# Function to extract CVSS data.
def get_cvss_data(metrics):
    for metric in metrics:
        if 'cvssV4_0' in metric:
            return metric['cvssV4_0']
        elif 'cvssV3_1' in metric:
            return metric['cvssV3_1']
        elif 'cvssV3_0' in metric:
            return metric['cvssV3_0']
        elif 'cvssV2_0' in metric:
            return metric['cvssV2_0']
    return {}


# Function to extract the impacted product name
def get_impacted_product(affected_list):
    if affected_list:
        product_info = affected_list[0]  # Assumes the first element has the product information
        return product_info.get('product', 'Unknown Product')
    return 'Unknown Product'


# Function to extract impacted product versions
def get_impacted_product_versions(affected_list):
    if affected_list and 'versions' in affected_list[0]:
        versions = affected_list[0]['versions']
        version_details = [f"{v.get('version', 'Unspecified')} ({v.get('status', 'No status')})" for v in versions]
        return '; '.join(version_details)
    return 'No versions available'


# Append "Mitre_" to column names if not already present
def prefix_column_names(columns):
    return ['Mitre_' + col if not col.startswith('Mitre_') else col for col in columns]


# Process and convert JSON to CSV
def process_json_to_dataframe(input_file_path):
    try:
        with open(input_file_path, 'r', encoding='utf-8') as file:
            data = json.load(file)
    except FileNotFoundError:
        logging.error(f"File not found: {input_file_path}")
        return
    except json.JSONDecodeError:
        logging.error(f"Error decoding JSON: {input_file_path}")
        return

    all_records = []

    for record in data:

        # Grab all data from json
        cna = record.get('containers', {}).get('cna', {})
        cve_meta = record.get('cveMetadata', {})
        state = cve_meta.get('state', '')
        descriptions = cna.get('descriptions', [{}])[0].get('value', '')
        problem_description = cna.get('problemTypes', [{}])[0].get('descriptions', [{}])[0].get('description', '')
        references = [ref.get('url') for ref in cna.get('references', []) if 'url' in ref]
        references_str = '; '.join(references)
        cvss_data = get_cvss_data(cna.get('metrics', {}))
        impacted_product = get_impacted_product(cna.get('affected', []))
        impacted_product_versions = get_impacted_product_versions(cna.get('affected', []))

        # Save everything to a dictionary
        record_data = {
            'CVE_ID': cve_meta.get('cveId', 'Unknown CVE_ID'),
            'Date_Published': cve_meta.get('datePublished', 'Unknown Date Published'),
            'Date_Updated': cve_meta.get('dateUpdated', 'Unknown Date Updated'),
            'Description': descriptions,
            'Problem_Description': problem_description,
            'References': references_str,
            'Assigner_Org': cve_meta.get('assignerShortName', 'Unknown Assigner Org'),
            'Impacted_Product': impacted_product,
            'Impacted_Product_Versions': impacted_product_versions,
            'Report_State': state,
            **cvss_data
        }

        all_records.append(record_data)

    if all_records:
        df = pd.DataFrame(all_records)
        # Apply the column prefix modification here
        df.columns = prefix_column_names(df.columns)
        logging.info(f"Processed and saved: {input_file_path}")
        return df
    else:
        logging.warning(f"No data processed for: {input_file_path}")


# Process all JSON files in the directory
def process_all_files():

    # Directory paths
    input_directory = "ProcessedFiles/Mitre CVE Json Year/"
    output_file = f"ProcessedFiles/mitre_combined_data_{date.today()}.xlsx"

    # Create dataframes variable
    dataframes = []

    for root, dirs, files in os.walk(input_directory):
        for file in glob.glob(os.path.join(root, '*.json')):
            logging.info(f"Starting processing of file: {file}")
            dataframes.append(process_json_to_dataframe(file))

    # Concatenate all dataframes. Note: Will throw error if excel writer is not used.
    try:
        combined_df = pd.concat(dataframes, ignore_index=True)
        with pd.ExcelWriter(
                output_file,
                engine="xlsxwriter",
                engine_kwargs={'options': {'strings_to_formulas': False, 'strings_to_urls': False}}
        ) as writer:
            combined_df.to_excel(writer, index=False)
        logging.info(f"All CSV files have been combined into {output_file}")
        return combined_df
    except Exception as e:
        logging.error(f"Failed to combine files: {e}")
