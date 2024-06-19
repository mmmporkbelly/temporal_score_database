"""
Thank you to Dan K for the retry code for get/post requests
"""

import random
import requests
import time
from requests import Response


class Retry:
    total_retries = 11
    start_threshold = 1
    retry_statuses = frozenset({413, 429, 500, 503})

    @staticmethod
    def check_for_retries(resp, params, headers, url) -> Response:
        retry_counter = 0
        while resp.status_code in Retry.retry_statuses and retry_counter < Retry.total_retries:
            print("Initiating retry...")
            try:
                if resp.status_code == 429 and 'Retry-After' in resp.headers and resp.headers['Retry-After'] != '':
                    Retry.start_threshold = int(resp.headers['Retry-After'])

                # Added extra line of code for 503 error in case of NVD
                elif resp.status_code == 503:
                    print("503 Error from NVD. Sleeping for 5 minutes.")
                    time.sleep(300)
            except ValueError:
                print(
                    f'Error assigning Retry-After response header value {resp.headers["Retry-After"]} \
                    to start_threshold property, using previously assigned value.')
            jitter = random.triangular(Retry.start_threshold, Retry.start_threshold + 1)
            time.sleep(jitter)
            resp = requests.get(url, headers=headers, params=params)
            retry_counter = retry_counter + 1

        return resp

    @staticmethod
    def check_for_post_retries(resp, data, headers, url) -> Response:
        retry_counter = 0

        while resp.status_code in Retry.retry_statuses and retry_counter < Retry.total_retries:
            try:
                if resp.status_code == 429 and 'Retry-After' in resp.headers and resp.headers['Retry-After'] != '':
                    Retry.start_threshold = int(resp.headers['Retry-After'])
            except ValueError:
                print(
                    f'Error assigning Retry-After response header value {resp.headers["Retry-After"]} \
                        to start_threshold property, using previously assigned value.')
            jitter = random.triangular(Retry.start_threshold, Retry.start_threshold + 1)
            time.sleep(jitter)
            resp = requests.post(url, headers=headers, data=data)
            retry_counter = retry_counter + 1

        return resp
