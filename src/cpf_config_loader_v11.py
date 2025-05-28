from __init__ import SRC_DIR, CONFIG_FILENAME, CONFIG_FILENAME_FOR_USE, DATABASE_NAME
import json
from datetime import datetime, date
import os
from typing import Any
import re   
from pprint import pprint
import re 


#SRC_DIR = os.path.dirname(os.path.abspath(__file__))  # Path to the src directory
#CONFIG_FILENAME = os.path.join(SRC_DIR, 'cpf_config.json')  # Full path to the config file
#CONFIG_FILENAME_FOR_USE = os.path.join(SRC_DIR, 'cpf_config_flat.json')  # Full path to the config file for use
#DATABASE_NAME = os.path.join(SRC_DIR, 'cpf_simulation.db')  # Full path to the database file

DATE_FORMAT = "%Y-%m-%d"    
PATTERN  = r"\b\d{4}-\d{2}-\d{2}\b"

def custom_serializer(obj):
    """Custom serializer for non-serializable objects like datetime."""
    if isinstance(obj, (datetime,date)):
        return obj.strftime(DATE_FORMAT)
    raise TypeError(f"Type {type(obj)} not serializable")

class CPFConfig:
    """
    Load config from JSON, converting date strings to datetime objects.
    Also supports saving the config back to JSON (round-trip).
    Includes features for flattening/unflattening dictionaries, resolving formulas, and retrieving nested values.
    """

    def __init__(self, config_filename: str = None):
        self.src_dir = SRC_DIR
        self.path = os.path.join(SRC_DIR, config_filename)  # Full path to the config fileconfig_filename
        self.data = None
        self.load_config()
        self.set_attributes_from_dict(self.data)
        #delattr(self,'data')  # Remove the data attribute after setting attributes'
        delattr(self,'src_dir')  # Remove the src_dir attribute after setting attributes'
        delattr(self,'path')  # Remove the path attribute after setting attributes'

    def load_config(self):
        """
        Load the configuration file and parse its contents.
        """
        if not os.path.exists(self.path):
            raise FileNotFoundError(f"Configuration file not found: {self.path}")
        try:
            with open(self.path, 'r') as myfile:
                config_data = json.load(myfile)
        except json.JSONDecodeError as e:
            raise ValueError(f"Error decoding JSON: {e}")

        # Ensure the data is a dictionary
        if isinstance(config_data, list):
            config_data = {str(index): item for index, item in enumerate(config_data)}
        elif not isinstance(config_data, dict):
            raise ValueError(f"Invalid configuration format: Expected a dictionary, got {type(config_data)}")
        self.data = config_data

    def get_keys_and_values(self):
        """
        Extract all keys and values from the configuration as two separate lists.
        Only leaf keys (with their full path) and their values are included.
        """
        keys = []
        values = []

        def extract(data, parent_key=""):
            if isinstance(data, dict):
                for key, value in data.items():
                    full_key = f"{parent_key}{key}" if parent_key else key
                    if isinstance(value, (dict, list)):
                        extract(value, full_key)
                    else:
                        keys.append(full_key)
                        values.append(value)
            elif isinstance(data, list):
                for index, item in enumerate(data):
                    full_key = f"{parent_key}[{index}]"
                    if isinstance(item, (dict, list)):
                        extract(item, full_key)
                    else:
                        keys.append(full_key)
                        values.append(item)

        extract(self.data)
        return keys, values


    
    def set_attributes_from_dict(self, value: dict):
        keys = []
        values = []
   
        keys,values = self.get_keys_and_values()  
        #iterate in both list and set the attributes
        for key, val in zip(keys, values):
            setattr(self, key, val)
            
            
def main():
    # Load the configuration
    config = CPFConfig(config_filename=CONFIG_FILENAME)
   # print(config.excess_balance)
    newdict = {}
  
    print("\nAttributes of the config object:")
    for attr in dir(config):
        if not attr.startswith("__") and not callable(getattr(config, attr)):
            print(f"{attr}: {getattr(config, attr)}")
            newdict[attr] = getattr(config, attr)
    with open(CONFIG_FILENAME_FOR_USE, 'w') as f:
        json.dump(newdict, f, indent=4, default=custom_serializer)
    
    
    
    

if __name__ == "__main__":
    main()














































