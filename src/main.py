#from __init__ import (
#    SRC_DIR, CONFIG_FILENAME, FLAT_FILENAME, USER_FILE, PATH
#)
import streamlit as st
import bcrypt
import json
import os
from cpf_config_loader_v11 import CPFConfig
from datetime import datetime, date
import sys
import subprocess
import webbrowser
from pathlib import Path

st.set_page_config(page_title="CPF Simulation Setup", layout="wide")
# Dynamically determine the src directory
SRC_DIR = Path(__file__).resolve().parent

# Configuration file paths
CONFIG_FILENAME = os.path.join(SRC_DIR, 'cpf_config_flat.json')
FLAT_FILENAME = os.path.join(SRC_DIR, 'cpf_config_flat.json')
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


def load_users():
    if not os.path.exists(USER_FILE):
        with open(USER_FILE, "w") as f:
            json.dump({}, f)
        st.warning("No users found. Please register a new user.")
        return {}
    with open(USER_FILE, "r") as f:
        return json.load(f)

def save_users(users):
    with open(USER_FILE, "w") as f:
        json.dump(users, f)

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def check_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())

def migrate_secret_answers(users):
    changed = False
    for _, data in users.items():
        secret_answer = data.get("secret_answer", "")
        if not (isinstance(secret_answer, str) and secret_answer.startswith("$2")):
            data["secret_answer"] = hash_password(secret_answer.lower())
            changed = True
    if changed:
        save_users(users)

def show_registration(users):
    st.header("Register New Account")
    username = st.text_input("New Username", key="reg_user")
    new_password1 = st.text_input("New Password", type="password", key="reg_pass1")
    new_password2 = st.text_input("Confirm Password", type="password", key="reg_pass2")
    secret_question = st.selectbox(
        "Secret Question",
        options=["Name of your pet ?", "Favourite book ?", "Your First School ?"],
        key="reg_secret_question"
    )
    secret_answer = st.text_input("Secret Answer", key="reg_secret_answer")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Create Account", key="create_account"):
            if username in users:
                st.error("Username already exists.")
            elif new_password1 != new_password2:
                st.error("Passwords do not match.")
            elif not new_password1 or not new_password2:
                st.error("Password fields cannot be empty.")
            elif not secret_answer:
                st.error("Secret answer cannot be empty.")
            else:
                users[username] = {
                "password": hash_password(new_password1),
                "secret_question": secret_question,
                "secret_answer": hash_password(secret_answer.lower())
            }
            save_users(users)
            st.success("Account created successfully! Please log in.")
            st.session_state["register_mode"] = False
            st.rerun()
    with col2:
        if st.button("Cancel", key="cancel_registration"):
            st.session_state["register_mode"] = False
            st.rerun()

def show_forgot_password(users, username):
    if not username or username not in users:
        st.error("Invalid or missing username. Please go back and enter a valid username.")
        if st.button("Go Back", key="reset_go_back"):
            st.session_state["reset_mode"] = False
            st.rerun()
        return

    st.session_state["reset_mode"] = True
    user_secret_question = users[username]["secret_question"]
    st.info(f"Secret Question: **{user_secret_question}**")
    secret_answer_input = st.text_input("Your Answer to Secret Question", key="reset_secret_answer")
    col1, col2 = st.columns(2)

    with col1:
        if st.button("Submit", key="reset_submit"):
            if check_password(secret_answer_input.lower(), users[username]["secret_answer"]):
                st.session_state["reset_verified"] = True
                st.success("Secret answer verified! Please enter your new password.")
                st.rerun()
            else:
                st.error("Incorrect answer to the secret question.")

    with col2:
        if st.button("Cancel", key="reset_cancel"):
            st.session_state["reset_mode"] = False
            st.session_state["reset_verified"] = False
            st.rerun()

    if st.session_state.get("reset_verified", False):
        new_password = st.text_input("Enter new password", type="password", key="reset_pass")
        col3, col4 = st.columns(2)

        with col3:
            if st.button("Reset Password", key="reset_password"):
                if not new_password:
                    st.error("Password cannot be empty.")
                else:
                    users[username]["password"] = hash_password(new_password)
                    save_users(users)
                    st.success("Password reset successful! Please log in with your new password.")
                    st.session_state["reset_mode"] = False
                    st.session_state["reset_verified"] = False
                    st.rerun()

        with col4:
            if st.button("Quit", key="reset_quit"):
                st.session_state["reset_mode"] = False
                st.session_state["reset_verified"] = False
                st.write("The application has been stopped. You can now close this tab.")
                st.stop()  # Halt the Streamlit script

def show_login(myusers):
    st.header("🔒 Login")
    username = st.text_input("Username", key="login_username_input")
    password = st.text_input("Password", type="password", key="login_password_input")
    secret_question = st.selectbox(
        "Secret Question",
        options=["Name of your pet ?", "Favourite book ?", "Your First School ?"],
        key="login_secret_question"
    )
    secret_answer = st.text_input("Secret Answer", key="login_secret_answer")
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        if st.button("Login", key="login_button"):
            if (
                username in myusers and
                check_password(password, myusers[username]["password"]) and
                myusers[username]["secret_question"] == secret_question and
                check_password(secret_answer.lower(), myusers[username]["secret_answer"])
            ):
                st.session_state["logged_in"] = True
                st.session_state["Main Page"] = True
                st.session_state["register_mode"] = False
                st.session_state["reset_mode"] = False
                st.session_state["reset_verified"] = False
                st.session_state["username"] = username  # Save username in session state
                st.success("Login successful!")
                st.rerun()
            else:
                st.error("Invalid username, password, or secret answer.")

    with col2:
        if st.button("Forgot", key="forgot_button"):
            st.session_state["reset_mode"] = True
            st.session_state["username"] = username  # Save username for reset flow
            st.rerun()

    with col3:
        if st.button("Register", key="register_button"):
            st.session_state["register_mode"] = True
            st.rerun()

    with col4:
        if st.button("Quit", key="quit_button"):
            st.session_state["logged_in"] = False
            st.session_state["Main Page"] = False
            st.session_state["register_mode"] = False
            st.session_state["reset_mode"] = False
            st.session_state["reset_verified"] = False
            st.session_state["username"] = ""  # Clear the username
            st.write("The application has been stopped. You can now close this tab.")
            st.stop()  # Halt the Streamlit script
            
def show_main_page():
    st.title("🧾 CPF Simulation Configurator")
    st.subheader("🔧 Edit Parameters")
    config = CPFConfig(CONFIG_FILENAME)
    updated_config = {}
    
    # Get all attributes from the config object
    for attr in dir(config):
        if not attr.startswith("__") and not callable(getattr(config, attr)):
            value = getattr(config, attr)
            if isinstance(value, (int, float)):
                updated_value = st.number_input(attr, value=value)
            elif isinstance(value, str):
                updated_value = st.text_input(attr, value=value)
            else:
                updated_value = st.text_area(attr, value=json.dumps(value, default=str))
            updated_config[attr] = updated_value

    # Create a container for the buttons
    button_container = st.container()
    with button_container:
        col1, col2, col3, col4, col5, col6 = st.columns(6)
        with col1:
            if st.button("💾 Save",key="save_configuration"):
                with open(CONFIG_FILENAME_FOR_USE, "w") as f:
                    json.dump(updated_config, f, indent=4, default=str)
                st.success("Configuration saved successfully!")
        with col2:
            run_sim = st.button("Run Simulation",key="run_simulation")
        with col3:
            if st.button("🚀 Run CSV Report",key="run_csv"):
                try:
                    python_executable = sys.executable
                    result = subprocess.run(
                        [python_executable, os.path.join(SRC_DIR, "cpf_build_reports_v1.py")],
                        check=True, capture_output=True, text=True
                    )
                    st.success("CSV report generated successfully!")
                    st.code(result.stdout)
                except subprocess.CalledProcessError as e:
                    st.error("CSV report generation failed:")
                    st.code(e.stderr or str(e))
        with col4:
            if st.button("📊 Run Analysis",key="run_analysis"):
                try:
                    python_executable = sys.executable
                    result = subprocess.run(
                        [python_executable, os.path.join(SRC_DIR, "cpf_analysis_v1.py")],
                        check=True, capture_output=True, text=True
                    )
                    st.success("Analysis completed successfully!")
                    st.code(result.stdout)
                except subprocess.CalledProcessError as e:
                    st.error("Analysis failed:")
                    st.code(e.stderr or str(e))
        with col5:
            import pandas as pd
            import dicttoxml
            report_file_path = os.path.join(SRC_DIR, "cpf_report.csv")
            try:
                report_df = pd.read_csv(report_file_path)
                report_dict = report_df.to_dict(orient="records")
                xml_data = dicttoxml.dicttoxml(report_dict, custom_root="CPFReport", attr_type=False)
                st.download_button(key="download_xml",
                    label="Download XML",
                    data=xml_data,
                    file_name="cpf_report.xml",
                    mime="application/xml"
                )
            except FileNotFoundError:
                st.error(f"File not found: {report_file_path}")
            except Exception as e:
                st.error(f"An error occurred while generating the XML: {e}")
        with col6:
            if st.button("🛑 EXIT",key="exit_button"):
                st.write("Exiting the application...")
                st.session_state["logged_in"] = False
                st.session_state["Main Page"] = False
                st.session_state["register_mode"] = False
                st.session_state["reset_mode"] = False
                st.session_state["reset_verified"] = False
                os._exit(0)

    # Create a separate container for simulation results
    if run_sim:
        with st.container():
            st.markdown("---")  # Add a separator
            st.subheader("Simulation Results")
            try:
                python_executable = sys.executable
                result = subprocess.run(
                    [python_executable, os.path.join(SRC_DIR, "cpf_run_simulation_v9.py")],
                    check=True, capture_output=True, text=True
                )
                output_path = os.path.join(SRC_DIR, "simulation_output.html")
                
                # Write the output file with proper HTML structure
                with open(output_path, "w") as f:
                    f.write(f"""
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <title>Simulation Results</title>
                        <style>
                            body {{ font-family: Arial, sans-serif; margin: 20px; }}
                            pre {{ white-space: pre-wrap; word-wrap: break-word; }}
                        </style>
                    </head>
                    <body>
                        <h1>Simulation Results</h1>
                        <pre>{result.stdout}</pre>
                    </body>
                    </html>
                    """)
                
                if os.path.exists(output_path):
                    st.success("Simulation completed successfully!")
                    with open(output_path, 'r') as f:
                        html_content = f.read()
                    st.components.v1.html(html_content, height=600, scrolling=True)
                else:
                    st.error(f"Output file was not created at: {output_path}")
                    
            except subprocess.CalledProcessError as e:
                st.error("Simulation failed:")
                st.code(e.stderr or str(e))

def main():
    users = load_users()
    migrate_secret_answers(users)

    # Initialize session state variables if not set
    for key, val in [
        ("logged_in", False),
        ("register_mode", False),
        ("reset_mode", False),
        ("reset_verified", False),
        ("Main Page", False),
        ("username", ""),  # Add userna#me to session state
    ]:
        if key not in st.session_state:
            st.session_state[key] = val

    # Main logic flow 
    if st.session_state["logged_in"] and st.session_state["Main Page"]:
        show_main_page()
    elif st.session_state["register_mode"]:
        show_registration(users)
    elif st.session_state["reset_mode"]:
        show_forgot_password(users, st.session_state["username"])
    else:
        show_login(users)

if __name__ == "__main__":
    main()