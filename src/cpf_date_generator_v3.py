# cpf_date_generator_v2.py
from __init__ import SRC_DIR, CONFIG_FILENAME, LOG_FILE_PATH, DATE_DICT, DATE_LIST
from datetime import date, datetime # Ensure date is imported
from dateutil.relativedelta import relativedelta
from calendar import monthrange
from cpf_data_saver_v3 import DataSaver
import os
import json,csv
from typing import Any

#SRC_DIR = os.path.dirname(os.path.abspath(__file__))  # Path to the src directory
#CONFIG_FILENAME = os.path.join(SRC_DIR, 'cpf_config.json')  # Full path to the config file
#LOG_FILE_PATH = os.path.join(SRC_DIR, "cpf_log_file.csv")  # Log file path inside src folder
DATE_KEYS = ['start_date', 'end_date', 'birth_date']
DATE_FORMAT = "%Y-%m-%d"
#DATE_DICT = os.path.join(SRC_DIR, 'cpf_date_dict.json')  # Path to the date dictionary file
#DATE_LIST = os.path.join(SRC_DIR, 'cpf_date_list.csv')  # Path to the date list file

def serialize(obj):
    for key, value in obj.items():
        if isinstance(value, (datetime, date)):
            obj[key] = value.strftime(DATE_FORMAT)
        elif isinstance(value, dict):
            serialize(value)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, (datetime, date)):
                    item = item.strftime(DATE_FORMAT)
                elif isinstance(item, dict):
                    serialize(item)
    return obj
def custom_serializer(obj):
    """Custom serializer for non-serializable objects like datetime."""
    if isinstance(obj, datetime):
        return obj.strftime("%Y-%m-%d %H:%M:%S")
    raise TypeError(f"Type {type(obj)} not serializable")

class DateGenerator(object):
    """
    Class to generate a dictionary of dates with start/end of month and age.
    Expects input dates are datetime.date objects.
    date_dict[date_key] = {
    # Ensure period_start isn't before the actual simulation start_d
    'period_start': max(period_start, start_date),
    'period_end': period_end,
    'age': age_at_period_end
}
    """
    def __init__(self, start_date, end_date, birth_date):
        self.start_date = self.convert_date_strings('start_date', start_date)
        self.end_date = self.convert_date_strings('end_date', end_date)
        self.birth_date = self.convert_date_strings('birth_date', birth_date)
        self.data = None
        self.date_dict = {}
        self.date_list = []

    def convert_date_strings(self, key:str, date_str:str):    
        """
        Convert date strings in the configuration to datetime objects.
        """
        
        if isinstance(date_str, str) and key.lower() in DATE_KEYS:
            try:
                return datetime.strptime(date_str, DATE_FORMAT).date()
            except ValueError:
                pass
        elif isinstance(date_str, (date, datetime)):
            return date_str
        else:
            raise ValueError(f"Invalid date format for {key}: {date_str}. Expected format: YYYY-MM-DD")
    
    def get_data(self,   keys : Any ):
        """
        Get data from the date_dict based on the provided keys.
        """
        if isinstance(keys, str):
            keys = [keys]
        elif isinstance(keys, list):
            keys = keys
        else:
            raise TypeError("keys must be a string or a list of strings")
        
        data = {}
        for key in keys:
            if key in self.date_dict:
                data[key] = self.date_dict[key]
            else:
                raise KeyError(f"Key {key} not found in date_dict")
        return data     
    
    def generate_date_dict(self):
        """
        Generates a dictionary of dates with start/end of month and age.
        Expects input dates are datetime.date objects.
        date_dict[date_key] = {
        'period_start': max(period_start, start_date),
        'period_end': period_end,
        'age': age_at_period_end
            }
        """
       #if isinstance(self.start_date, str):
       #    self.convert_dates_to_datetime(self.start_date)
       #elif isinstance(self.end_date, str):
       #    self.convert_dates_to_datetime(self.end_date)
       #elif isinstance(self.birth_date, str):
       #    self.convert_dates_to_datetime(self.birth_date)
       #elif isinstance(self.start_date, (date, datetime)):
       #    self.start_date = self.start_date
       #elif isinstance(self.end_date, (date, datetime)):
       #    self.end_date = self.end_date
       #elif isinstance(self.birth_date, (date, datetime)):
       #    self.birth_date = self.birth_date
       #else:
       #    raise TypeError("start_date, end_date, and birth_date must be date or datetime objects")                                    
    
        self.date_dict = {}
        # Start from the first day of the start month
        current_date =date(self.start_date.year, self.start_date.month, 1)
    
        while current_date <= self.end_date:
            date_list = []
            year = current_date.year
            month = current_date.month
    
            # Calculate period start and end as date objects
            period_start = date(year, month, 1) # First day of month
            last_day_of_month = monthrange(year, month)[1]
            period_end = date(year, month, last_day_of_month) # Last day of month
    
            # Comparison is now between two date objects
            if self.start_date > period_end:
                # If the simulation start date is after the end of the current month, skip
                current_date = current_date + relativedelta(months=1)
                continue
            
            # Calculate age at the end of the period
            age_at_period_end = relativedelta(period_end, self.birth_date).years
    
            date_key = period_end.strftime('%Y-%m')
            self.date_dict[date_key] = {
                # Ensure period_start isn't before the actual simulation start_date
                'period_start': max(period_start, self.start_date),
                'period_end': period_end,
                'age': age_at_period_end
            }
            date_list.append(self.date_dict)  # Append the current date_dict to the list
            # Move to the first day of the next month (date + relativedelta -> date)
            current_date = current_date + relativedelta(months=1)
        #    print(f'Procfessing Date Dictionary key = {date_key}, {age_at_period_end}')  # Debugging line to print each entry
           # self.save_file('date_dict', format='pickle')  # Save the date_dict to file after each entry
            self.data = self.date_dict
        return self.date_dict
    
#    def convert_dates_to_datetime(self, date_str):
#        """
#        Convert date strings to datetime.date objects.
#        """
#        if isinstance(date_str, str):
#            try:
#                date_obj = datetime.strptime(date_str, "%Y-%m-%d").date()
#                return date_obj
#            except ValueError:
#                raise ValueError(f"Invalid date format: {date_str}. Expected format: YYYY-MM-DD")
       
    def save_file(self, file , format='csv'):
        """
        Save the date_dict to a file in the specified format.
        """
       
        if format == 'csv':
            with open(DATE_LIST, 'w') as f:
                for key, value in self.date_dict.items():
                    f.write(f"{key},{value['period_start']},{value['period_end']},{value['age']}\n")
        elif format == 'json':
            serialized = serialize(file)
            with open(DATE_DICT, 'w') as f:
                json.dump(serialized, f, default=custom_serializer)
        else:
            raise ValueError("Unsupported format. Use 'csv' or 'json'.")
        
        
        
        
        
        
        
        
        
        


       
       
       
        
    
        
        
   
   
    

if __name__ == "__main__":
    # Example usage
    start_date = '1945-04-01'
    end_date = '2080-07-31'
    birth_date = '1945-04-19'
    dategen = DateGenerator(start_date, end_date, birth_date)
    date_dict = dategen.generate_date_dict()
   # dategen.save # Save the date_dict to file after generation
    for date_key, period_info in date_dict.items():
        print(f"Period {date_key}: Start: {period_info['period_start']}, End: {period_info['period_end']}, Age: {period_info['age']}")