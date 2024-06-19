import logging
from subprocess import Popen, PIPE


# Function to update or clone a GitHub repository containing MITRE CVE data
def download_mitre_file():

    try:
        repo_url = "https://github.com/CVEProject/cvelistV5.git"
        target_directory = f"Downloads/MitreCVE"
        command = ['git', 'clone', repo_url, target_directory]
        process = Popen(command, stdout=PIPE, stderr=PIPE, universal_newlines=True)
        stdout, stderr = process.communicate()

        logging.debug(f"Mitre DB Git Clone output: {stdout}")
        if stderr:
            logging.error(f"Mitre DB Git Clone error: {stderr}")

        if process.returncode == 0:
            print(f"Mitre DB Git Clone completed successfully.")
            logging.info(f"Mitre DB Git Clone completed successfully.")
        else:
            raise RuntimeError(f"Failed to Clone Mitre repository. Please check the log for more details.")
    except Exception as e:
        logging.error(f"Error Mitre DB Git Clone: {e}")
