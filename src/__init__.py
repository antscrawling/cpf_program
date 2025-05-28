from pathlib import Path
import os

# Dynamically determine the src directory
SRC_DIR = Path(__file__).resolve().parent

# Configuration file paths
CONFIG_FILENAME = SRC_DIR / "cpf_config.json"
LOG_FILE_PATH =   SRC_DIR / "cpf_log_file.csv"
DATABASE_NAME =   SRC_DIR /"cpf_simulation.db"
# Other global variables
APP_NAME = "CPF Program"
VERSION = "1.0.0"
AUTHOR = "Your Name"