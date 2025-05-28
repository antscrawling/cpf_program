from pathlib import Path
import os

# Dynamically determine the src directory
SRC_DIR = Path(__file__).resolve().parent

# Configuration file paths
CONFIG_FILENAME = os.path.join(SRC_DIR, 'cpf_config.json')
FLAT_FILENAME = os.path.join(SRC_DIR, 'test_config1.json')
CONFIG_FILENAME_FOR_USE = CONFIG_FILENAME
USER_FILE = os.path.join(SRC_DIR, "users.json")
LOG_FILE_PATH = os.path.join(SRC_DIR, 'cpf_log_file.csv')
DATABASE_NAME = os.path.join(SRC_DIR, 'cpf_simulation.db')
DATE_DICT = os.path.join(SRC_DIR, 'cpf_date_dict.json')  # Path to the date dictionary file
DATE_LIST = os.path.join(SRC_DIR, 'cpf_date_list.csv')  # Path to the date list file
# Output file paths
CPF_REPORT = os.path.join(SRC_DIR, 'cpf_report.csv')  # Full path to the report file
OUTPUT_MISMATCHES = os.path.join(SRC_DIR, 'cpf_mismatches.csv')  # Output file for mismatches
OUTPUT_BALANCES = os.path.join(SRC_DIR, 'cpf_final_balances.csv')  # Output file for final balances

# Other global variables
APP_NAME = "CPF Program"
VERSION = "1.0.0"
AUTHOR = "Your Name"
username: str = ""  # Global variable for username