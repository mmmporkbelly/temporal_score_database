"""Upload a file to an S3 bucket

    :param file_name: File to upload
    :param bucket: Bucket to upload to
    :param object_name: S3 object name. If not specified then file_name is used
    :return: True if file was uploaded, else False
"""

import logging
import boto3
from botocore.exceptions import ClientError
from datetime import date
import os


# Upload all xlsx and log files
def upload_all_files(log_file_path):
    try:
        # Establish boto client
        s3_client = boto3.client('s3')

        # ADD BUCKET NAME HERE
        bucket = ''

        # Grab all xlsx filenames
        excel_files = []
        for root, dirs, files in os.walk('/ProcessedFiles'):
            for file in files:
                if file.endswith('.xlsx'):
                    excel_files.append([os.path.join(root, file), file])


        # Upload excel files
        for file in excel_files:
            try:
                if file[1] == f'final_result_{date.today()}.xlsx':
                    response = s3_client.upload_file(file[0], bucket, f"FinalResult/{file[1]}")
                else:
                    response = s3_client.upload_file(file[0], bucket, f"ProcessedFiles/{file[1]}")
            except Exception as e:
                logging.error(f"Error uploading: {e}")

        # Upload log file - unneeded for now, since cloudwatch also gets the logs.
        # try:
        #     response = s3_client.upload_file(log_file_path, bucket, log_file_path)
        # except Exception as e:
        #     logging.error(e)
        #     upload_successful = False

        # Send notification if upload was successful

        client = boto3.client('sns')

        # ADD ARN HERE IF USING SNS
        snsArn = ''

        # ADD CUSTOM MESSAGE
        message = ''

        response = client.publish(
            TopicArn=snsArn,
            Message=message,
            Subject='Temporal Score Database'
        )
    except Exception as e:
        client = boto3.client('sns')
        # ADD ARN HERE IF USING SNS
        snsArn = ''

        # ADD CUSTOM MESSAGE
        message = ''

        response = client.publish(
            TopicArn=snsArn,
            Message=message,
            Subject='Temporal Score Database'
        )
