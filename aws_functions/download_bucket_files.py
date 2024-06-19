import boto3
from botocore.exceptions import ClientError
import logging
from os import path, makedirs
from datetime import date, timedelta


def download_nvd_file():
    # Only do this if it is not the first day of the month. Data from NVD should be refreshed monthly
    first_day = date.today().replace(day=1)
    if first_day != date.today():
        # Calculate the day before
        query_date = date.today() - timedelta(days=1)
        print(query_date)
        # Establish bucket

        # ADD BUCKET NAME HERE
        bucket = ''
        key = f'ProcessedFiles/nvd_{query_date}.xlsx'
        s3 = boto3.client('s3')

        # Make Processed Files folder
        log_path = 'ProcessedFiles/'
        if not path.exists(log_path):
            makedirs(log_path)

        try:
            s3.download_file(bucket, key, key)
        except ClientError as e:
            if e.response['Error']['Code'] == "404":
                print("The object does not exist.")
            logging.error(f"{e}: NVD file does not exist")
