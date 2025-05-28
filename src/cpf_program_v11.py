from __init__ import SRC_DIR, CONFIG_FILENAME, CONFIG_FILENAME_FOR_USE, DATABASE_NAME, LOG_FILE_PATH
import atexit
from datetime import datetime
import csv
import json
from cpf_config_loader_v11 import CPFConfig
from cpf_data_saver_v3 import DataSaver  # Import DataSaver class
from multiprocessing import Process, Queue
import sqlite3
import os
from datetime import date, datetime
from itertools import count

# Dynamically determine the src directory
#SRC_DIR = os.path.dirname(os.path.abspath(__file__))  # Path to the src directory
#CONFIG_FILENAME = os.path.join(SRC_DIR, 'cpf_config.json')  # Full path to the config file
#LOG_FILE_PATH = os.path.join(SRC_DIR, "cpf_log_file.csv")  # Log file path inside src folder
DATE_KEYS = ['startdate', 'enddate', 'birthdate']
DATE_FORMAT = "%Y-%m-%d"

# Load configuration
#config = ConfigLoader(CONFIG_FILENAME)


# Define the worker function at the top level (outside the class)
def _save_log_worker(queue, filename):
    """Worker process to save logs to file."""
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "date",
                "transaction_reference",
                "age",  # Include 'age' in the fieldnames
                "account",
                "old_balance",
                "new_balance",
                "amount",
                "type",
                "message",
            ],
        )
        writer.writeheader()
        while True:
            log_entry = queue.get()
            if log_entry == "STOP":
                break
            try:
                writer.writerow(log_entry)
            except ValueError as e:
                print(f"Error writing log entry: {e}")
                print(f"Log entry: {log_entry}")


def custom_serializer(obj):
    """Custom serializer for non-serializable objects like datetime."""
    if isinstance(obj, datetime):
        return obj.strftime("%Y-%m-%d %H:%M:%S")
    raise TypeError(f"Type {type(obj)} not serializable")


class CPFAccount:
    def __init__(self, config_loader):  # Accept config_loader
        self.config = config_loader  # Store the config_loader instance
        self.current_date: datetime = datetime.now()
        self.date_key: str = None
        self.message: str = None
        self.startdate = None
        self.enddate = None
        self.birthdate = None
        self.salary = self.config.salary
        self.age = 0
        self.payout = 0.0

        # Account balances and logs
        self._oa_balance = 0.0
        self._sa_balance = 0.0
        self._ma_balance = 0.0
        self._ra_balance = 0.0
        self._excess_balance = 0.0
        self._loan_balance = 0.0
        self.start_reference = 100000000        
        self.counter = count(1)
        self.trandaction_reference = 0
        self.dbcounter = count(1)
        self.dbreference = 0
        
        # Log saving setup
        self.log_queue = Queue()
        self.log_process = Process(
            target=_save_log_worker, args=(self.log_queue, LOG_FILE_PATH)
        )
        self.log_process.daemon = (
            True  # Ensure the process terminates with the main program
        )
        self.log_process.start()

        # Register cleanup function
        atexit.register(self.close_log_writer)
        
    def add_db_reference(self):
        self.dbreference = self.start_reference + next(self.dbcounter)
        return self.dbreference
    
    def add_transaction_reference(self):
        self.trandaction_reference = self.start_reference + next(self.counter)
        return self.trandaction_reference
        
    def save_log_to_file(self, log_entry):
        """Send log entry to the worker process."""
        if self.log_process.is_alive():
            self.log_queue.put(log_entry)
        else:
            print("Warning: Log writer process is not running.")

    def close_log_writer(self):
        """Stop the log writer process."""
        if self.log_process.is_alive():
            try:
                self.log_queue.put("STOP")
                self.log_process.join(timeout=5)  # Wait for the process to terminate
            except Exception as e:
                print(f"Error while closing log writer: {e}")

    @property
    def oa_balance(self):
        return self._oa_balance, self._oa_message

    @oa_balance.setter
    def oa_balance(self, data):
        if isinstance(data, (tuple, list)) and len(data) == 2:
            value, self.message = data
        else:
            value, self.message = float(data), "no message"
        diff = value - self._oa_balance
        # loglist_entry.append()
        log_entry = {
            "date": self.current_date.strftime("%Y-%m-%d"),
            "transaction_reference" : self.add_transaction_reference(),
            "age": self.age,
            "account": "oa",
            "old_balance": self._oa_balance.__round__(2),
            "new_balance": value.__round__(2),
            "amount": diff.__round__(2),
            "type": "inflow" if diff > 0 else ("outflow" if diff < 0 else "no change"),
            "message": f"oa-{self.message}-{diff:.2f}",
        }
        self._oa_balance = value.__round__(2)
        self._oa_message = self.message
        # self.save_log_to_file(log_entry) 
        self.save_log_to_file(log_entry)  # Send log entry to the worker process

    @property
    def sa_balance(self):
        return self._sa_balance, self._sa_message

    @sa_balance.setter
    def sa_balance(self, data):
        if isinstance(data, (tuple, list)) and len(data) == 2:
            value, self.message = data
        else:
            # Ensure value is treated as float if data is not a tuple/list
            value, message = (
                float(data),
                "no message",
            )  # Assuming data should be numeric
        diff = value - self._sa_balance
        log_entry = {
            # Ensure current_date is set before logging
            "date": self.current_date.strftime("%Y-%m-%d"),
            "transaction_reference" : self.add_transaction_reference(),
            "age": self.age,
            "account": "sa",  # Add account identifier
            "old_balance": self._sa_balance.__round__(2),
            "new_balance": value.__round__(2),
            "amount": diff.__round__(2),
            "type": "inflow" if diff > 0 else ("outflow" if diff < 0 else "no change"),
            "message": f"sa-{self.message}-{diff:.2f}",  # Format diff for consistency
        }
        # self._sa_log.append(log_entry) # Optional: Keep in-memory log if needed
        self._sa_balance = value.__round__(2)
        self._sa_message = self.message

        # Save the log entry using multiprocessing
        self.save_log_to_file(log_entry) 

    @property
    def ma_balance(self):
        return self._ma_balance, self._ma_message

    @ma_balance.setter
    def ma_balance(self, data):
        if isinstance(data, (tuple, list)) and len(data) == 2:
            value, self.message = data
        else:
            value, self.message = float(data), "no message"
        diff = value - self._ma_balance
        log_entry = {
            "date": self.current_date.strftime("%Y-%m-%d"),
            "transaction_reference" : self.add_transaction_reference(),
            "age": self.age,
            "account": "ma",
            "old_balance": self._ma_balance.__round__(2),
            "new_balance": value.__round__(2),
            "amount": diff.__round__(2),
            "type": "inflow" if diff > 0 else ("outflow" if diff < 0 else "no change"),
            "message": f"ma-{self.message}-{diff:.2f}",
        }
        self._ma_balance = value.__round__(2)
        self._ma_message = self.message
        self.save_log_to_file(log_entry) 

    @property
    def ra_balance(self):
        return self._ra_balance, self._ra_message

    @ra_balance.setter
    def ra_balance(self, data):
        if isinstance(data, (tuple, list)) and len(data) == 2:
            value, self.message = data
        else:
            value, self.message = float(data), "no message"
        diff = value - self._ra_balance
        log_entry = {
            "date": self.current_date.strftime("%Y-%m-%d"),
            "transaction_reference" : self.add_transaction_reference(),
            "age": self.age,
            "account": "ra",
            "old_balance": self._ra_balance.__round__(2),
            "new_balance": value.__round__(2),
            "amount": diff.__round__(2),
            "type": "inflow" if diff > 0 else ("outflow" if diff < 0 else "no change"),
            "message": f"ra-{self.message}-{diff:.2f}",
        }
        self._ra_balance = value
        self._ra_message = self.message
        self.save_log_to_file(log_entry) 

    @property
    def excess_balance(self):
        return self._excess_balance, self._excess_message

    @excess_balance.setter
    def excess_balance(self, data):
        if isinstance(data, (tuple, list)) and len(data) == 2:
            value, self.message = data
        else:
            value, self.message = float(data), "no message"
        diff = value - self._excess_balance
        log_entry = {
            "date": self.current_date.strftime("%Y-%m-%d"),
            "transaction_reference" : self.add_transaction_reference(),
            "age": self.age,
            "account": "excess",
            "old_balance": self._excess_balance.__round__(2),
            "new_balance": value.__round__(2),
            "amount": diff.__round__(2),
            "type": "inflow" if diff > 0 else ("outflow" if diff < 0 else "no change"),
            "message": f"excess-{self.message}-{diff:.2f}",
        }
        self._excess_balance = value.__round__(2)
        self._excess_message = self.message
        self.save_log_to_file(log_entry) 

    @property
    def loan_balance(self):
        return self._loan_balance, self._loan_message

    @loan_balance.setter
    def loan_balance(self, data):
        if isinstance(data, (tuple, list)) and len(data) == 2:
            value, self.message = data
        else:
            value, self.message = float(data), "no message"
        diff = value - self._loan_balance
        log_entry = {
            "date": self.current_date.strftime("%Y-%m-%d"),
            "transaction_reference" : self.add_transaction_reference(),
            "age": self.age,
            "account": "loan",
            "old_balance": self._loan_balance.__round__(2),
            "new_balance": value.__round__(2),
            "amount": diff.__round__(2),
            "type": "inflow" if diff > 0 else ("outflow" if diff < 0 else "no change"),
            "message": f"loan-{self.message}-{diff:.2f}",
        }
        self._loan_balance = value.__round__(2)
        self._loan_message = self.message
        self.save_log_to_file(log_entry) 

    @property
    def combined_balance(self):
        # Always calculate the combined balance dynamically
        self._combined_balance = (
            self._oa_balance + self._sa_balance + self._ma_balance + self._ra_balance
        )
        return self._combined_balance, self._combined_message

    @combined_balance.setter
    def combined_balance(self, data):
        # Setter logic remains unchanged
        if isinstance(data, (tuple, list)) and len(data) == 2:
            value, self.message = data
        else:
            value, self.message = float(data), "no message"
        diff = value - self._combined_balance
        log_entry = {
            "date": self.current_date.strftime("%Y-%m-%d"),
            "transaction_reference" : self.add_transaction_reference(),
            "age": self.age,
            "account": "combined",
            "old_balance": self._combined_balance.__round__(2),
            "new_balance": value.__round__(2),
            "amount": diff.__round__(2),
            "type": "inflow" if diff > 0 else ("outflow" if diff < 0 else "no change"),
            "message": f"combined-{self.message}-{diff:.2f}",
        }
        self._combined_balance = value.__round__(2)
        self._combined_message = self.message
        self.save_log_to_file(log_entry) 

    @property
    def combinedbelow55_balance(self):
        # Dynamically calculate the combined below 55 balance if age <= 55
        if self.current_date and self.birthdate:
            age = (self.current_date.year - self.birthdate.year) - (
                (self.current_date.month, self.current_date.day)
                < (self.birthdate.month, self.birthdate.day)
            )
            if age < 55:
                self._combinedbelow55_balance = (
                    self._oa_balance + self._sa_balance + self._ma_balance
                )
        return self._combinedbelow55_balance, self._combinedbelow55_balance_message

    @combinedbelow55_balance.setter
    def combinedbelow55_balance(self, data):
        # Setter logic remains unchanged
        if isinstance(data, (tuple, list)) and len(data) == 2:
            value, self.message = data
        else:
            value, self.message = float(data), "no message"
        diff = value - self._combinedbelow55_balance
        log_entry = {
            "date": self.current_date.strftime("%Y-%m-%d"),
            "transaction_reference" : self.add_transaction_reference(),
            "age": self.age,
            "account": "combined_below_55",
            "old_balance": self._combinedbelow55_balance.__round__(2),
            "new_balance": value.__round__(2),
            "amount": diff.__round__(2),
            "type": "inflow" if diff > 0 else ("outflow" if diff < 0 else "no change"),
            "message": f"combined_below_55-{self.message}-{diff:.2f}",
        }
        self._combinedbelow55_balance = value.__round__(2)
        self._combinedbelow55_balance_message = self.message
        self.save_log_to_file(log_entry) 

    @property
    def combinedabove55_balance(self):
        # Dynamically calculate the combined above 55 balance if age >= 55
        if self.current_date and self.birthdate:
            age = (self.current_date.year - self.birthdate.year) - (
                (self.current_date.month, self.current_date.day)
                < (self.birthdate.month, self.birthdate.day)
            )
            if age >= 55:
                self._combinedabove55_balance = (
                    self._oa_balance + self._ra_balance + self._ma_balance
                )
        return self._combinedabove55_balance, self._combinedabove55_balance_message

    @combinedabove55_balance.setter
    def combinedabove55_balance(self, data):
        # Setter logic remains unchanged
        if isinstance(data, (tuple, list)) and len(data) == 2:
            value, self.message = data
        else:
            value, self.message = float(data), "no message"
        diff = value - self._combinedabove55_balance
        log_entry = {
            "date": self.current_date.strftime("%Y-%m-%d"),
            "transaction_reference" : self.add_transaction_reference(),
            "age": self.age,
            "account": "combined_above_55",
            "old_balance": self._combinedabove55_balance.__round__(2),
            "new_balance": value.__round__(2),
            "amount": diff.__round__(2),
            "type": "inflow" if diff > 0 else ("outflow" if diff < 0 else "no change"),
            "message": f"combined_above_55-{self.message}-{diff:.2f}",
        }
        self._combinedabove55_balance = value.__round__(2)
        self._combinedabove55_balance_message = self.message
        self.save_log_to_file(log_entry) 

    def __enter__(self):
        """Enter the runtime context related to this object."""
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """Exit the runtime context and ensure resources are released."""
        self.close_log_writer()
        return False

    def close(self):
        """Ensure the log writer process is properly closed."""
        self.close_log_writer()

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
        
    def get_date_dict(self, startdate, enddate, birthdate):
        """Generate a date dictionary.  #this is called once only"""
        print(
            "Warning: get_date_dict needs implementation in CPFAccount or be imported correctly."
        )
        from cpf_date_generator_v3 import generate_date_dict

        return generate_date_dict(startdate, enddate, birthdate)

    def update_balance(self, account: str, new_balance: float, message: str):
        """
        Sets the account balance to the specified new_balance and logs the change.
        The logged 'amount' reflects the difference from the old balance.
        # this is called every month
        """
        valid_accounts = ["oa", "sa", "ma", "ra", "loan", "excess"]
        if account not in valid_accounts:
            print(f"Error: Invalid account name for update_balance: {account}")
            return  # Or raise ValueError
        # Set the new balance using the provided value
        setattr(self, f"_{account}_balance", new_balance)

    def record_inflow(self, account: str, amount: float, message: str = "") -> None:
        """Records an inflow of funds into a specified account."""
        valid_accounts = ["oa", "sa", "ma", "ra", "loan", "excess"]
        if account not in valid_accounts:
            print(f"Error: Invalid account name for record_inflow: {account}")
            return

        if not isinstance(amount, (int, float)) or abs(amount) < 1e-9:
            return  # Skip invalid or zero inflow

        # Get current balance safely
        current_balance = getattr(self, f"_{account}_balance", 0.0)
        new_balance = current_balance + amount

        # Use the property setter to update balance and trigger logging
        setattr(self, f"{account}_balance", (new_balance.__round__(2), message))

    def record_outflow(self, account: str, amount: float, message: str = "") -> None:
        """Records an outflow of funds from a specified account."""
        valid_accounts = ["oa", "sa", "ma", "ra", "loan", "excess"]
        if account not in valid_accounts:
            print(f"Error: Invalid account name for record_outflow: {account}")
            return

        if not isinstance(amount, (int, float)) or abs(amount) < 1e-9:
            return  # Skip invalid or zero outflow

        # Get current balance safely
        current_balance = getattr(self, f"_{account}_balance", 0.0)
        new_balance = current_balance - amount

        # Use the property setter to update balance and trigger logging
        setattr(self, f"{account}_balance", (new_balance.__round__(2), message))

    def insert_data(
        self,
        conn,
        date_key,
        dbreference,
        age,
        _oa_balance,
        _sa_balance,
        _ma_balance,
        _ra_balance,
        _loan_balance,
        _excess_balance,
        payout,
        message
    ):
        """Inserts CPF data into the database."""
        try:
            sql = """
                INSERT OR REPLACE INTO cpf_data (
                    date_key, dbreference, age, oa_balance, sa_balance, ma_balance, ra_balance, loan_balance, excess_balance, cpf_payout, message
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """
            cur = conn.cursor()
            cur.execute(sql, (
                date_key,
                dbreference,
                age,
                _oa_balance,
                _sa_balance,
                _ma_balance,
                _ra_balance,
                _loan_balance,
                _excess_balance,
                payout,
                message
            ))
            conn.commit()
        except (sqlite3.Error, sqlite3.DatabaseError) as e:
            print(f"Database insertion error: {e}")
        except SyntaxError as f:
            print(f"SQL Syntax error: {f}")
            

    def calculate_cpf_allocation(self, account: str) -> float:
        """
        Calculates the allocation amount for a specific CPF account based on age and total CPF contribution.
        """
        # Ensure total contributions are calculated
        if self.total_contribution == 0.0:
            raise ValueError(
                "Total contributions have not been calculated. Call `calculate_total_contributions` first."
            )

        # Determine allocation rates based on age
        if self.age < 55:
            alloc_percentage = getattr(self.config,f"allocationbelow55{account}", 0)
            self._oa_allocation55 = alloc_percentage * self.total_contribution
            self._sa_allocation55 = alloc_percentage * self.total_contribution
            self._ma_allocation55 = alloc_percentage * self.total_contribution
            self._ra_allocation55 = 0.0

        elif 55 <= self.age < 60:
            alloc_percentage = getattr(self.config,
                f"allocationabove55{account}56to60", 0
            )
            self._oa_allocation_5560 = alloc_percentage * self.total_contribution
            self._sa_allocation_5560 = (
                alloc_percentage * self.total_contribution if self.age <= 55 else 0.0
            )
            self._ma_allocation_5560 = alloc_percentage * self.total_contribution
            self._ra_allocation_5560 = (
                alloc_percentage * self.total_contribution if self.age > 55 else 0.0
            )
        elif 60 <= self.age < 65:
            alloc_percentage = getattr(self.config,f"allocationabove55{account}61to65",0)
            self._oa_allocation6065 = alloc_percentage * self.total_contribution
            self._ma_allocation6065 = alloc_percentage * self.total_contribution
            self._ra_allocation6065 = alloc_percentage * self.total_contribution

        elif 65 <= self.age < 70:
            alloc_percentage = getattr(self.config,
                f"allocation_above_55{account}66_to_70", 0
            )
            self._oa_allocation6570 = alloc_percentage * self.total_contribution
            self._ma_allocation6570 = alloc_percentage * self.total_contribution
            self._ra_allocation6570 = alloc_percentage * self.total_contribution

        else:  # age >= 70
            alloc_percentage = getattr(self.config,
                f"allocation_above_55{account}above_70", 0
            )
            self._oa_allocation70 = alloc_percentage * self.total_contribution
            self._ma_allocation70 = alloc_percentage * self.total_contribution
            self._ra_allocation70 = alloc_percentage * self.total_contribution

        # Calculate the allocation amount
        allocation_amount = self.total_contribution * alloc_percentage
        return allocation_amount

    def compute_and_add_allocation(self):
        """
        Compute the CPF allocation amounts for each category (oa, sa, ma, ra) based on the age
        and add them to the configuration using the add_key_value method.
        """
        # Retrieve the salary cap
        salary_cap = getattr(self.config,"salarycap", 0)
        self.calculate_total_contributions()
    #    allocation = {}
    #    mydict = {}
    #    with open(CONFIG_FILENAME, "r") as file:
    #        mydict = json.load(file)
    #    # Determine the correct age bracket for contribution rates
    #    allocation = {
    #        "allocation_below_55": {
    #            "oa": {
    #                "allocation": 0.6217,
    #                "amount": 0.6217 * self.total_contribution,
    #            },
    #            "sa": {
    #                "allocation": 0.1621,
    #                "amount": 0.1621 * self.total_contribution,
    #            },
    #            "ma": {
    #                "allocation": 0.2162,
    #                "amount": 0.2162 * self.total_contribution,
    #            },
    #        },
    #        "allocation_above_55": {
    #            "oa": {
    #                "56_to_60": {
    #                    "allocation": 0.3694,
    #                    "amount": 0.3694 * self.total_contribution,
    #                },
    #                "61_to_65": {
    #                    "allocation": 0.149,
    #                    "amount": 0.149 * self.total_contribution,
    #                },
    #                "66_to_70": {
    #                    "allocation": 0.0607,
    #                    "amount": 0.0607 * self.total_contribution,
    #                },
    #                "above_70": {
    #                    "allocation": 0.08,
    #                    "amount": 0.08 * self.total_contribution,
    #                },
    #            },
    #            "sa": {"allocation": 0.00, "amount": 0.0},
    #            "ma": {
    #                "56_to_60": {
    #                    "allocation": 0.323,
    #                    "amount": 0.323 * self.total_contribution,
    #                },
    #                "61_to_65": {
    #                    "allocation": 0.4468,
    #                    "amount": 0.4468 * self.total_contribution,
    #                },
    #                "66_to_70": {
    #                    "allocation": 0.6363,
    #                    "amount": 0.6363 * self.total_contribution,
    #                },
    #                "above_70": {
    #                    "allocation": 0.84,
    #                    "amount": 0.84 * self.total_contribution,
    #                },
    #            },
    #            "ra": {
    #                "56_to_60": {
    #                    "allocation": 0.3076,
    #                    "amount": self.total_contribution * 0.3076,
    #                },
    #                "61_to_65": {
    #                    "allocation": 0.4042,
    #                    "amount": self.total_contribution * 0.4042,
    #                },
    #                "66_to_70": {
    #                    "allocation": 0.303,
    #                    "amount": self.total_contribution * 0.303,
    #                },
    #                "above_70": {
    #                    "allocation": 0.08,
    #                    "amount": self.total_contribution * 0.08,
    #                },
    #            },
    #        },
    #    }
    #    allocation.update(mydict)
    #    with open(CONFIG_FILENAME, "w") as file:
    #        json.dump(allocation, file, indent=4)

    # self.config.add_key_value(allocation, None)
    # self.config.save()

    def calculate_combined_balance(self):
        """calculate the combined balance based on age"""
        oa_balance = 0.0
        sa_balance = 0.0
        ma_balance = 0.0
        ra_balance = 0.0

        if self.age < 55:
            #                       10_000                     -->  10_000
            oa_balance = min(getattr(self, "_oa_balance", 0), 20_000)
            #                       50_000                    -->   40_000
            sa_balance = min(getattr(self, "_sa_balance", 0), 40_000)
            if (oa_balance + sa_balance) == 60_000:
                return oa_balance, sa_balance, 0.00, 0.00
            ma_balance = min(getattr(self, "_ma_balance", 0), 40_000)
            if (oa_balance + sa_balance + ma_balance) == 60_000:
                return oa_balance, sa_balance, ma_balance, 0.00
            ra_balance = 0.00
            return oa_balance, sa_balance, ma_balance, ra_balance
        elif self.age >= 55:
            #                       50000                     -->  20000
            oa_balance = min(getattr(self, "_oa_balance", 0), 20_000)
            # sa_balance = min(getattr(self, '_sa_balance', 0), 10_000)
            # if (oa_balance + sa_balance) == 30_000:
            #    return oa_balance, sa_balance, 0.00, 0.00
            ma_balance = min(getattr(self, "_ma_balance", 0), 30_000 - oa_balance)
            if (oa_balance + ma_balance) == 30_000:
                return oa_balance, sa_balance, ma_balance, ra_balance
            ra_balance = min(getattr(self, "_ra_balance", 0), 30_000)
            if (oa_balance + ma_balance + ra_balance) == 60_000:
                return oa_balance, sa_balance, ma_balance, ra_balance
            return oa_balance, sa_balance, ma_balance, ra_balance

    def calculate_interest_on_cpf(self, account: str, amount: float) -> float:
        """
        Apply interest to all CPF accounts at the end of the year.
        This is called every December - 12 of every year.
        """
        # Retrieve interest rates from the configuration
        oa_rate = (
            self.config.interestratesoabelow55
            if self.age < 55
            else self.config.interestratesoaabove55
        )
        sa_rate = self.config.interestratessa
        ma_rate = self.config.interestratesma
        ra_rate = self.config.interestratesra

        # Calculate interest based on the account type
        if account == "oa":
            return round((oa_rate / 100 / 12) * amount, 2)
        elif account == "sa":
            return round((sa_rate / 100 / 12) * amount, 2)
        elif account == "ma":
            return round((ma_rate / 100 / 12) * amount, 2)
        elif account == "ra":
            return round((ra_rate / 100 / 12) * amount, 2)
        else:
            raise ValueError("Invalid account type. Must be 'oa', 'sa', 'ma', or 'ra'.")

    def calculate_extra_interest(self):
        """
        Apply extra interest to SA and MA accounts based on age.
        This is called every December - 12 of every year.
        """
        # extra_interest = self.config.getdata(['extra_interest'], {})
        extra_interest_rate = self.config.extrainterestbelow55
        extra_interest1 = self.config.extrainterestfirst30kabove55
        
        extra_interest2 = self.config.extrainterestnext30kabove55
        
        oa_interest = 0.0
        sa_interest = 0.0
        ma_interest = 0.0
        ra_interest = 0.0
        oa_balance, sa_balance, ma_balance, ra_balance = (
            self.calculate_combined_balance()
        )

        if self.age < 55:
            oa_interest = oa_balance * (extra_interest_rate / 100 / 12)
            sa_interest = sa_balance * (extra_interest_rate / 100 / 12)
            ma_interest = ma_balance * (extra_interest_rate / 100 / 12)
            ra_interest = 0.0
            return (0, oa_interest + sa_interest, ma_interest, ra_interest)
        elif self.age >= 55:
            first_30k = min((oa_balance + sa_balance + ma_balance + ra_balance), 30_000)
            next_30k = min(
                oa_balance + sa_balance + ma_balance + ra_balance - first_30k, 30_000
            )

            if first_30k == 30_000:
                ra_interest = 30_000 * (extra_interest1 / 100 / 12)
            elif next_30k == 30_000:
                ra_interest = 30_000 * (extra_interest2 / 100 / 12)
            else:
                ra_interest = 0.0

            return (oa_interest, sa_interest, ma_interest, ra_interest)

    def get_cpf_contribution_rate(self, age: int, is_employee: bool) -> float:
        """
        Retrieve CPF contribution rate based on age and employment status.
        """
        if age < 55:
            rates = self.config.cpfcontributionratesbelow55
        elif 55 <= age < 60:
            rates = self.config.cpfcontributionrates55to60
        elif 60 <= age < 65:
            rates = self.config.cpfcontributionrates60to65
        elif 65 <= age < 70:
            rates = self.config.cpfcontributionrates65to70
        else:
            rates = self.config.cpfcontributionratesabove70

        rate_key = "employee" if is_employee else "employer"
        if age < 55:
            age_bracket = "below55"
        elif 55 <= age < 60:
            age_bracket = "55to60"
        elif 60 <= age < 65:
            age_bracket = "60to65"
        elif 65 <= age < 70:
            age_bracket = "65to70"
        else:
            age_bracket = "above70"
        return getattr(self.config,
            f"cpfcontributionrates{age_bracket}{rate_key}", 0.0
        )

    def calculate_cpf_contribution(self, is_employee: bool) -> float:
        """
        Calculates CPF contribution based on salary, age, and employment status.
        """
        capped_salary = min(self.salary, self.config.salarycap)

        # Determine the correct age bracket for contribution rates
        if self.age <= 55:
            age_bracket = "below55"
        elif 55 < self.age <= 60:
            age_bracket = "55to60"
        elif 60 < self.age <= 65:
            age_bracket = "60to65"
        elif 65 < self.age <= 70:
            age_bracket = "65to70"
        else:  # age > 70
            age_bracket = "above70"

        # Retrieve the contribution rate
        rate_key = "employee" if is_employee else "employer"
        rate = getattr(self.config,
            f"cpfcontributionrates{age_bracket}{rate_key}", 0.0
        )

        # Calculate the contribution
        contribution = capped_salary * rate
        if is_employee:
            self.employee_contribution = contribution
        else:
            self.employer_contribution = contribution

        return contribution

    def calculate_total_contributions(self) -> float:
        """
        Calculates the total CPF contributions (employee + employer) based on salary and age.
        Updates the `self.total_contribution` attribute.
        """
        # Calculate employee and employer contributions
        employee_contribution = self.calculate_cpf_contribution(is_employee=True)
        employer_contribution = self.calculate_cpf_contribution(is_employee=False)

        # Update the total contributions
        self.total_contribution = employee_contribution + employer_contribution
        # return self.total_contribution
        setattr(self, "total_contribution", self.total_contribution)

    def calculate_cpf_payout(self,types:str) -> float:
        """Calculates the CPF payout amount based on age and retirement sum.
        only starts at the age of 67
        """
        payout_age = self.config.cpfpayoutage
        payout = getattr(self.config,f"retirementsums{types}payout", 0.0)

        if self.age >= payout_age:
            self.payout = payout
            return self.payout
        else:
            return 0.0  # No payout before payout age

    def custom_serializer(self, obj):
        """called every month to save the log"""
        if isinstance(obj, datetime):
            return obj.strftime("%Y-%m-%d")  # Convert datetime to string
        raise TypeError("Type not serializable")

    def calculate_loan_payment(self):
        """Calculates the loan payment amount based on the current loan balance.
        this is called every month
        """
        # Example logic for calculating loan payment
        if self._loan_balance > 0:
            # Assuming a fixed interest rate and term for simplicity
            interest_rate = 0.03

    def calculate_the_loan_amortization(self):
        """Calculates the loan amortization schedule.
        this is called every month
        """
        # Example logic for calculating loan amortization
        if self._loan_balance > 0:
            # Assuming a fixed interest rate and term for simplicity
            interest_rate = 0.03  # should be coming from the config in the future.
            term_years = 30  # should come from the config in the future
            monthly_payment = (
                self._loan_balance
                * (interest_rate / 12)
                / (1 - (1 + interest_rate / 12) ** (-term_years * 12))
            )
            return monthly_payment
        else:
            return 0.0

    def loan_computation(self,year) -> float:
        """
        Calculates the loan payment amount based on the current loan balance and age.
        """
        if self._loan_balance <= 0:
            return 0.0

        # Determine the loan payment key based on age
        payment_key = "year12" if year <3 else "year3"
        payment_key = "year4" if year >=4 else payment_key
        loan_payment_amount = self.config.loanpayments
        return loan_payment_amount


if __name__ == "__main__":
    try:
        config_loader = CPFConfig(CONFIG_FILENAME)
        myself = CPFAccount(config_loader=config_loader)
        ages = [25, 55, 60, 65, 70, 75]
        for age in ages:
            myself.age = age
            myself.salary = 5000  # Example salary
            contribution = myself.calculate_cpf_contribution(is_employee=True)
            print(f"Age: {age}, Employee Contribution: {contribution}")

            # Test salary cap retrieval
            salary_cap = config_loader.salarycap
            print(f"Salary Cap: {salary_cap}")

        # Test CPF contribution calculation
        myself.salary = 6000  # Update salary for testing
        for age in ages:
            myself.age = age
            employee_contribution = myself.calculate_cpf_contribution(is_employee=True)
            employer_contribution = myself.calculate_cpf_contribution(is_employee=False)
            total_contribution = employee_contribution + employer_contribution
            print(
                f"Age: {age}, Employee Contribution: {employee_contribution}, Employer Contribution: {employer_contribution}, Total Contribution: {total_contribution}"
            )

        # Test multiprocessing log writer
        print("Testing multiprocessing log writer...")
        myself.date_key = datetime.now().strftime("%Y-%m-%d")
        myself.oa_balance = (1000.0, "Initial OA balance")
        myself.sa_balance = (2000.0, "Initial SA balance")
        myself.record_inflow("oa", 500.0, "Monthly contribution")
        myself.record_outflow("sa", 300.0, "Medical expenses")
        myself.close_log_writer()  # Ensure logs are flushed to the file
        print("Log writer test completed. Check the log file for entries.")

    except Exception as e:
        print(f"An error occurred: {e}")
