from __init__ import SRC_DIR, CONFIG_FILENAME, LOG_FILE_PATH
import pandas as pd
from datetime import datetime, date
from dateutil.relativedelta import relativedelta
from typing import Any
import os
from pathlib import Path

#a=os.path.dirname(os.path.abspath(__file__))
#b=Path(__file__).resolve().parent 
#SRC_DIR = "/src" #Path(__file__).resolve().parent  # Dynamically determine the src directory
#CONFIG_FILENAME = os.path.join( "src/cpf_config.json")
#LOG_FILE_PATH = os.path.join("src/cpf_log_file.csv")  # Log file path inside src folder

#PATH="$HOME/miniconda3/bin:$PATcd srH"

class CPFLogEntry:
    def __init__(self, csv_file_path: str):
        self.csv_file_path = csv_file_path
        self.logs = None
        self.xdate: datetime.date = None
        self.reference : int = 0
        self.age: int = 0
        self.oa_balance: float = 0.0
        self.sa_balance: float = 0.0
        self.ma_balance: float = 0.0
        self.ra_balance: float = 0.0
        self.loan_balance: float = 0.0
        self.excess_balance: float = 0.0
        self.inflow: float = 0.0
        self.outflow: float = 0.0
        self.flow_type: str = ''
        self.message: str = ''
        self.birth_date = datetime(1974, 7, 6).date()

        # Load logs from the CSV file
        self._load_logs()

    def _load_logs(self):
        """
        Load logs from the CSV file into a DataFrame.
        """
        try:
            self.logs = pd.read_csv(self.csv_file_path)
        except FileNotFoundError:
            raise FileNotFoundError(f"CSV file not found: {self.csv_file_path}")
        except pd.errors.ParserError as e:
            raise ValueError(f"Error parsing CSV file: {e}")

    def convert_dates_to_date(self, xdate: Any, birth_date: Any) -> None:
        """
        Convert xdate and birth_date to date objects and set them as attributes.
        """
        if isinstance(birth_date, str):
            birth_date = datetime.strptime(birth_date, "%Y-%m-%d").date()
        elif isinstance(birth_date, datetime):
            birth_date = birth_date.date()
        elif not isinstance(birth_date, date):
            raise TypeError(f"birth_date must be a date object, got {type(birth_date)}")

        if isinstance(xdate, str):
            xdate = datetime.strptime(xdate, "%Y-%m-%d").date()
        elif isinstance(xdate, datetime):
            xdate = xdate.date()
        elif not isinstance(xdate, date):
            raise TypeError(f"xdate must be a date object, got {type(xdate)}")

        self.birth_date = birth_date
        self.xdate = xdate

    def calculate_age(self) -> int:
        """
        Calculate the age based on the xdate and birth_date.
        The age increments by 1 every July 6.
        """
        # Calculate the base age
        base_age = relativedelta(self.xdate, self.birth_date).years
        if self.xdate.month >= self.birth_date.month:
            base_age += 1
        return base_age

        # Check if the current date is on or after July 6 of the current year
       # current_year_birthday = date(self.xdate.year, self.birth_date.month, self.birth_date.day)
       # if self.xdate >= current_year_birthday:
       #     return base_age
       # else:
       #     return base_age - 1

    #def record_inflow(self, account: str, amount: float, message: str = "") -> None:
    #    """
    #    Records an inflow of funds into a specified account.
    #    """
    #    current_balance = getattr(self, f"{account}_balance", 0.0)
    #    new_balance = current_balance + amount
    #    setattr(self, f"{account}_balance", new_balance.__round__(2))
    #    self.inflow += amount
#
    #def record_outflow(self, account: str, amount: float, message: str = "") -> None:
    #    """
    #    Records an outflow of funds from a specified account.
    #    """
    #    current_balance = getattr(self, f"{account}_balance", 0.0)
    #    new_balance = current_balance - amount
    #    setattr(self, f"{account}_balance", new_balance.__round__(2))
    #    self.outflow += amount

    def build_report(self, output_format="csv"):
        """
        Build a report from the logs and save it as a CSV or Excel file.
        :param output_format: The format to save the report ("csv" or "excel").
        """
        report_data = []

        # Ensure logs are loaded
        if self.logs is None or self.logs.empty:
            raise ValueError("Logs data is empty or not loaded.")

        for _, log in self.logs.iterrows():
            # Extract log details
            date_str = log["date"]
            self.xdate = datetime.strptime(date_str, "%Y-%m-%d").date()
            self.reference = log["transaction_reference"]
            #try:
            #    # Parse the date into YYYY-MM format
            #    if len(date_str) == 7:  # Format: YYYY-MM
            #        self.xdate = datetime.strptime(date_str, "%Y-%m").date()
            #    elif len(date_str) == 10:  # Format: YYYY-MM-DD
            #        self.xdate = datetime.strptime(date_str, "%Y-%m-%d").date()
            #    else:
            #        raise ValueError(f"Invalid date format: {date_str}")
            #except ValueError as e:
            #    raise ValueError(f"Error parsing date '{date_str}': {e}")

            # Update the age for the current log entry
            self.age =  log["age"]

            self.flow_type = log["type"]
            self.message = log["message"]

            account = log["account"]
            amount = log["amount"].__round__(2)
            match account:
                case "oa":
                    self.oa_balance += amount
                case "sa":
                    self.sa_balance += amount
                case "ma":
                    self.ma_balance += amount
                case "ra":
                    self.ra_balance += amount
                case "loan":
                    if self.age == 55 and abs(amount) > 2000:
                        continue
                    else: self.loan_balance += amount
                case "excess":
                    self.excess_balance += amount
           #if self.flow_type == "inflow":
           #    self.record_inflow(account, amount, self.message)
           #elif self.flow_type == "outflow":
           #    self.record_outflow(account, amount, self.message)

            # Extract year-month for the DATE_KEY
           

            # Append the row to the report data, rounding amounts to 2 decimal places
            report_data.append({
                "DATE_KEY": self.xdate ,
                "REF": self.reference,
                "AGE": self.age,
                "ACCOUNT": account,
                "TYPE": self.flow_type,
                "INFLOW": amount.__round__(2) if self.flow_type == "inflow" else 0,
                "OUTFLOW": amount.__round__(2) if self.flow_type == "outflow" else 0,
                "OA":   self.oa_balance.__round__(2),  
                "SA":   self.sa_balance.__round__(2),  
                "MA":   self.ma_balance.__round__(2),  
                "RA":   self.ra_balance.__round__(2),  
                "LOANS":  self.loan_balance.__round__(2),   
                "EXCESS": self.excess_balance.__round__(2), 
                "MESSAGE": self.message
            })

        # Convert the report data to a DataFrame
        df = pd.DataFrame(report_data)

        # Save the report as CSV or Excel
        output_file = f"cpf_report.{output_format}"
        if output_format == "csv":
            df.to_csv(output_file, index=False)
        elif output_format == "excel":
            df.to_excel(output_file, index=False, engine="openpyxl")
        else:
            raise ValueError("Invalid output format. Use 'csv' or 'excel'.")

        print(f"Report saved as {output_file}")


if __name__ == "__main__":
    # Example usage
    #csv_file_path = "cpf_log_file.csv"
    cpflogs = CPFLogEntry(LOG_FILE_PATH)
    cpflogs.build_report()
























