# data_saver_v2.py
from __init__ import SRC_DIR, CONFIG_FILENAME, LOG_FILE_PATH
import json
import pickle
import shelve
#import pandas as pd
import csv
from datetime import datetime
from typing import Any, Union, List
import os

#SRC_DIR = os.path.dirname(os.path.abspath(__file__))  # Path to the src directory
#CONFIG_FILENAME = os.path.join(SRC_DIR, 'cpf_config.json')  # Full path to the config file
#LOG_FILE_PATH = os.path.join(SRC_DIR, "cpf_log_file.csv")  # Log file path inside src folder

def custom_serializer(obj):
    """Custom serializer for non-serializable objects like datetime."""
    if isinstance(obj, datetime):
        return obj.strftime("%Y-%m-%d %H:%M:%S")
    raise TypeError(f"Type {type(obj)} not serializable")


class DataSaver:
    """
    Class for efficient data storage (optional use). Supports streaming writes in pickle, shelve, or csv.
    """
    def __init__(self, format: str = None,filename: str = None):
        self.format = format.lower()
        self._data_list = []
        if self.format == 'pickle':
            self._file = open(filename, 'wb')
        elif self.format == 'json':
            self._file = None  # accumulate in memory
        elif self.format == 'shelve':
            self._shelf = shelve.open('filename', flag='n')
        elif self.format == 'csv':
            self._file = open(filename, 'w', newline='')
            self._csv_writer = None  # Initialize later when the first item is appended
        else:
            raise ValueError("Unsupported format for DataSaver")

    def append(self, item: Any):
        """Add an item to storage. If using pickle, shelve, or csv, write immediately to avoid memory use."""
        if self.format == 'pickle':
            pickle.dump(item, self._file)
        elif self.format == 'json':
            if isinstance(item, dict):
                self._data_list.append(item)
            else:
                raise ValueError("Item must be a dictionary for JSON format.")
        elif self.format == 'shelve':
            index = len(self._shelf)
            self._shelf[str(index)] = item
        elif self.format == 'csv':
            if isinstance(item, dict):
                if self._csv_writer is None:
                    # Initialize the CSV writer with the fieldnames from the first item
                    self._csv_writer = csv.DictWriter(self._file, fieldnames=item.keys())
                    self._csv_writer.writeheader()
                self._csv_writer.writerow(item)
            else:
                raise ValueError("Item must be a dictionary for CSV format.")
            
    def save_results(self,data: Union[dict, List], file_path: str, format: str = None):
        """
        Save the results data to file in the specified format: 'pickle' (binary), 'json', 'shelve', or 'csv'.
        """
        longfile = os.path.join(SRC_DIR, file_path)
        format = format.lower()
        if format == 'pickle':
            with open(longfile, 'wb') as f:
                pickle.dump(data, f)
        elif format == 'json':
            with open(longfile, 'w') as f:
                json.dump(data, f, indent=4,default=custom_serializer)
        elif format == 'shelve':
            # Save each item in a shelve DB (useful for incremental storage)
            with shelve.open(longfile, flag='n') as db:
                if isinstance(data, list):
                    for idx, item in enumerate(data):
                        db[str(idx)] = item
                elif isinstance(data, dict):
                    for key, item in data.items():
                        db[str(key)] = item
                else:
                    db['data'] = data
        elif format == 'csv':
            # Save list of dictionaries as a CSV file
            if isinstance(data, list) and all(isinstance(item, dict) for item in data):
                with open(longfile, 'w', newline='') as f:
                    fieldnames = ['date_key', 'period_start','period_end','age']
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(data)
            else:
                raise ValueError("Data must be a list of dictionaries to save as CSV.")
        else:
            raise ValueError(f"Unknown format: {format}")
    

    def close(self):
        """Finalize and close the storage, writing any accumulated data for JSON."""
        if self.format == 'pickle':
            self._file.close()
        elif self.format == 'json':
            with open(CONFIG_FILENAME, 'w') as f:
                json.dump(self._data_list, f, indent=4,default=custom_serializer)
        elif self.format == 'shelve':
            self._shelf.close()
        elif self.format == 'csv':
            self._file.close()
        self._data_list = []

    #def build_report(self, output_format="csv"):
    #    """
    #    Build a report from the logs and save it as a CSV or Excel file.
    #    :param output_format: The format to save the report ("csv" or "excel").
    #    """
    #    report_data = []
#
#


















































