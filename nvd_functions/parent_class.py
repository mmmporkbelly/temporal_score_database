"""
Parent dataframe, same thing that is used in exploit_df_functions
"""

import requests
from .get_retry import Retry
from datetime import date


# Foundational class for exploit dataframes
class CVEDataFrame:

    # Store dataframe given as argument
    def __init__(self, df, data_date):
        if not df.empty:
            self._df = df
        else:
            raise FileNotFoundError(f"Dataframe is empty")
        self._data_date = data_date

    # Function to make get request - implements Retry from get_retry.py
    @staticmethod
    def get_request(url, headers=None, params=None):
        res = requests.get(url, headers=headers)
        res = Retry.check_for_retries(res, params, headers, url)
        if res.status_code == 200:
            print("Received response from get request")
        return res

    # Function to return if date of dataframe is today
    def df_up_to_date(self):
        return date.today() == self._data_date

    # Function for querying if CVE exists in dataframe
    def query_for_cve(self, cve):
        try:
            result = self._df.query(f'cve == "{cve}"')
            if not result.empty:
                return result
            else:
                return False
        except Exception as e:
            raise FileNotFoundError(f"{e}: Cannot query")

    # Function to return df
    def all_df_data(self):
        return self._df

    # Function to return date of data
    def data_date(self):
        return self._data_date

