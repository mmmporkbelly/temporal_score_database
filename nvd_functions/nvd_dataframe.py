import pandas as pd
import logging
import re
import boto3
import json
import openpyxl     # This is a dependency for pd.read_excel
from botocore.exceptions import ClientError
from os import getenv, remove, path, makedirs
from dotenv import load_dotenv
from datetime import date, timedelta, datetime
from time import sleep
from glob import glob
from .parent_class import CVEDataFrame


# NVD DataFrame Class
class NVDDataFrame(CVEDataFrame):

    # Grab data from NVD
    def __init__(self):
        nvd_secret = False
        try:
            # Other option is to use AWS Secrets Manager
            # Add your client ID, client secret, token URL, and API endpoint URL
            # Get AWS Secret

            # ADD SECRET NAME AND REGION NAME
            secret_name = ""
            region_name = ""

            # Create a Secrets Manager client
            session = boto3.session.Session()
            client = session.client(
                service_name='secretsmanager',
                region_name=region_name
            )

            get_secret_value_response = client.get_secret_value(
                SecretId=secret_name
            )
            # Decrypts secret using the associated KMS key.
            secret = get_secret_value_response['SecretString']

            # Has to be formatted into dict
            secret = json.loads(secret)

            # ADD SECRET NAME HERE
            nvd_secret = secret['']
        except ClientError as e:
            logging.error(f"{e}: Can't retrieve secret")

        # Load NVD key, uncomment if using key.
        if not nvd_secret:
            load_dotenv()
            nvd_secret = getenv('NVD_SECRET')

        # Figure out last run date
        last_run = False
        for entry in glob("ProcessedFiles/nvd*.xlsx"):
            # Have to regex for the date
            date_regex = re.compile(r'(\d{4}-\d{2}-\d{2})')
            regex_result = re.findall(date_regex, str(entry))
            last_run = regex_result[0] if len(regex_result) > 0 else ''
            old_filename = entry
            break

        # Update file if last run. Create if not
        if last_run:
            nvd_data = NVDDataFrame.update_dataframe(nvd_secret, last_run, old_filename)
        else:
            nvd_data = NVDDataFrame.create_dataframe(nvd_secret)
        nvd_df = pd.DataFrame(nvd_data)
        nvd_df = nvd_df.astype(str)
        nvd_df.columns = NVDDataFrame.prefix_column_names(nvd_df.columns)
        logging.info('Writing NVD Dataframe to .xlsx')
        output_file = f'ProcessedFiles/nvd_{date.today()}.xlsx'
        with pd.ExcelWriter(
                output_file,
                engine="xlsxwriter",
                engine_kwargs={'options': {'strings_to_formulas': False, 'strings_to_urls': False}}
        ) as writer:
            nvd_df.to_excel(writer, index=False)
        logging.info(f"All CSV files have been combined into {output_file}")
        query_date = date.today()
        super().__init__(nvd_df, query_date)

    # Static method for creation of df
    @staticmethod
    def create_dataframe(key):
        nvd_secret = key
        start_index = 0
        url = 'https://services.nvd.nist.gov/rest/json/cves/2.0?noRejected&resultsPerPage=2000&startIndex='
        headers = {'API-Key': nvd_secret}
        count = 0
        nvd_accumulator = []

        logging.info("Starting NVD API Call...")
        # Keep making calls until response doesn't return vulns
        try:
            while True:
                count += 1
                request = url + str(start_index)
                response = CVEDataFrame.get_request(request, headers=headers)

                if response.status_code != 200:
                    logging.info(f'Failed to fetch data: {response.status_code}')
                    break

                data = response.json()
                vulnerabilities = data.get('vulnerabilities')
                if not vulnerabilities:
                    break

                if count == 1:
                    total_vulns = data.get('totalResults', 0)
                    logging.info(f"Total results: {total_vulns}")

                for entry in vulnerabilities:
                    processed_entry = NVDDataFrame.process_entry(entry)
                    if processed_entry:
                        nvd_accumulator.append(processed_entry)

                # Print total number of CVEs received so far
                total_received = start_index + len(data.get('vulnerabilities', []))
                logging.info(f"Page {count} received {len(data.get('vulnerabilities', []))} CVEs")
                logging.info(f"Total CVEs received so far: {total_received}")

                start_index += len(vulnerabilities)

                # Break if response responds less than 2000 vulns
                if len(vulnerabilities) < 2000:
                    break

                # Break if total received exceeds total vulns
                if int(total_received) > int(total_vulns):
                    break

                logging.info(f"{int(total_received) / int(total_vulns) * 100}% Done")
                sleep(6)  # Delay per NVD API requirements, be gentle <3
        except Exception as e:
            logging.info(f'Error Downloading data from NVD: {e}')
            raise e
        return nvd_accumulator

    # Update the NVD df
    @staticmethod
    def update_dataframe(key, last_run, old_nvd):
        nvd_secret = key
        start_index = 0

        # Get time, everything is in UTC
        current_time = datetime.now().replace(microsecond=0).isoformat()

        # Subtract two days for now from "last run" to cover all of our bases
        # Convert last run to a datetime object
        last_run = datetime.strptime(last_run, "%Y-%m-%d")

        # Subtract one day from the date
        last_run = last_run - timedelta(days=2)

        # Set URL and other params
        url = 'https://services.nvd.nist.gov/rest/json/cves/2.0?' \
              'noRejected&resultsPerPage=2000&' \
              f'lastModStartDate={last_run}T00:00:00.000&' \
              f'lastModEndDate={current_time}.000&' \
              'startIndex='
        headers = {'API-Key': nvd_secret}
        count = 0
        nvd_accumulator = []

        logging.info(f"NVD File found. Starting NVD API call to check deltas since {last_run}...")
        # Keep making calls until response doesn't return vulns
        try:
            while True:
                count += 1
                request = url + str(start_index)
                response = CVEDataFrame.get_request(request, headers=headers)

                if response.status_code != 200:
                    logging.info(f"Failed to fetch data: {response.status_code}")
                    break

                data = response.json()
                vulnerabilities = data.get('vulnerabilities')
                if not vulnerabilities:
                    break

                if count == 1:
                    total_vulns = data.get('totalResults', 0)
                    logging.info(f"Total results: {total_vulns}")

                for entry in vulnerabilities:
                    processed_entry = NVDDataFrame.process_entry(entry)
                    if processed_entry:
                        nvd_accumulator.append(processed_entry)

                # Print total number of CVEs received so far
                total_received = start_index + len(data.get('vulnerabilities', []))
                logging.info(f"Page {count} received {len(data.get('vulnerabilities', []))} CVEs")
                logging.info(f"Total CVEs received so far: {total_received}")

                start_index += len(vulnerabilities)

                # Break if response responds less than 2000 vulns
                if len(vulnerabilities) < 2000:
                    break

                # Break if total received exceeds total vulns
                if int(total_received) > int(total_vulns):
                    break

                logging.info(f"{int(total_received) / int(total_vulns) * 100}% Done")
                sleep(6)  # Delay per NVD API requirements, be gentle <3
        except Exception as e:
            logging.info(f'Error Downloading data from NVD: {e}')
            raise e

        # # Merge old and new dataframes
        # logging.info('Merging dataframes...')
        # old_nvd_df = pd.read_excel(old_nvd)
        # old_nvd_df.set_index('NVD_CVE_ID', inplace=True)
        # new_nvd_df = pd.DataFrame(nvd_accumulator)
        # new_nvd_df.columns = NVDDataFrame.prefix_column_names(new_nvd_df.columns)
        # new_nvd_df.set_index('NVD_CVE_ID', inplace=True)
        #
        # # Make sure everything is a str. Will get an error on pd.concat otherwise
        # old_nvd_df = old_nvd_df.astype(str)
        # new_nvd_df = new_nvd_df.astype(str)
        #
        # # Update values
        # old_nvd_df.update(new_nvd_df, overwrite=True)
        # old_nvd_df.reset_index(inplace=True)
        # new_nvd_df.reset_index(inplace=True)
        #
        # # Add differences
        # final_df = pd.concat([old_nvd_df, new_nvd_df], axis=0).drop_duplicates(subset=['NVD_CVE_ID'], keep='first')

        # Old logic was to update differences, then concat the two dataframes.
        # However, this should work with just concatting the two dataframes, dropping duplicates and keeping the last
        # instead of first. Delete below and go back to old method if this doesn't work
        logging.info('Merging dataframes...')
        old_nvd_df = pd.read_excel(old_nvd)
        new_nvd_df = pd.DataFrame(nvd_accumulator)
        new_nvd_df.columns = NVDDataFrame.prefix_column_names(new_nvd_df.columns)
        final_df = pd.concat([old_nvd_df, new_nvd_df], axis=0).drop_duplicates(subset=['NVD_CVE_ID'], keep='last')

        return final_df

    # Process nvd entry
    @staticmethod
    def process_entry(entry):
        cve = entry['cve']

        # Iterate for highest version
        highest_cvss_data = ''
        if "cvssMetricV4" in cve['metrics']:
            highest_cvss_data = "cvssMetricV4"
        elif "cvssMetricV31" in cve['metrics']:
            highest_cvss_data = "cvssMetricV31"
        elif "cvssMetricV30" in cve['metrics']:
            highest_cvss_data = "cvssMetricV30"
        elif "cvssMetricV2" in cve['metrics']:
            highest_cvss_data = "cvssMetricV2"
        if not highest_cvss_data:
            # skip if no CVSS data
            return None
        cvss_data_gen_primary = ((x, x['cvssData']) for x in cve['metrics'][highest_cvss_data] if
                                 x['type'] == 'Primary')
        cvss_data_gen_secondary = ((x, x['cvssData']) for x in cve['metrics'][highest_cvss_data] if
                                   x['type'] == 'Secondary')
        try:
            cvss_data, cvss_vector = next(cvss_data_gen_primary)
        except StopIteration:
            cvss_data, cvss_vector = next(cvss_data_gen_secondary)

        if not cvss_vector:
            cvss_vector = {}

        # Set those variables
        cve_id = cve.get('id', '')
        source_identifier = cve.get('sourceIdentifier', '')
        date_published = cve.get('published', '')
        date_updated = cve.get('lastModified', '')
        vulnerability_status = cve.get('vulnStatus', '')
        description = next((desc['value'] for desc in cve.get('descriptions', []) if desc['lang'] == 'en'), '')

        # Extract references, concatenate URLs, and count tags
        possible_tags = [
            "VENDOR ADVISORY", "THIRD PARTY ADVISORY", "MITRE REFERENCE", "MISC", "PATCH",
            "PERMISSION REQUIRED", "NOT USER FRIENDLY", "BROKEN LINK", "NEWS", "OFFICIAL",
            "TOOL", "EXPLOIT", "PRODUCT", "RELEASE NOTES"
        ]

        # Extract references, concatenate URLs, check for patch
        references = cve.get('references', [])
        urls = {}
        patch = False
        has_reference = ''
        if len(references) > 0:
            has_reference = True
        for ref in references:
            if 'url' in ref:
                urls[ref.get('url', '')] = ref.get('tags', [])
            for tag in ref.get('tags', []):
                normalized_tag = tag.upper()  # Normalize tags to match possible_tags
                if normalized_tag == "PATCH":
                    patch = True

        # Extract CWEs
        weaknesses = cve.get('weaknesses', [])
        cwes = []
        for weakness in weaknesses:
            for cpe in weakness.get('description', []):
                cwes.append(cpe.get('value', ''))

        # Extract CPEs
        cpes = cve.get('configurations', [])

        if cve:
            new_row = {
                'NVD_CVE_ID': cve_id,
                'NVD_Source_Identifier': source_identifier,
                'NVD_Date_Published': date_published,
                'NVD_Date_Updated': date_updated,
                'NVD_Vulnerability_Status': vulnerability_status,
                'NVD_Description': description,
                'NVD_Reference_Urls': urls,
                'NVD_CPEs': cpes,
                'NVD_CWEs': cwes,
                'NVD_Patch': patch,
                'NVD_has_reference': has_reference,
                **cvss_vector

            }

            return new_row

        else:
            return None

    # Static method for making sure "NVD" is in front of all column names
    @staticmethod
    def prefix_column_names(columns):
        return ['NVD_' + col if not col.startswith('NVD_') else col for col in columns]
