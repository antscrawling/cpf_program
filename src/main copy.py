import streamlit as st
import bcrypt
import json
import os
from cpf_config_loader_v11 import CPFConfig
from datetime import datetime, date
import sys
import subprocess
import webbrowser

# Set page config FIRST


PATH = os.path.dirname(os.path.abspath(__file__))  # Dynamically determine the src directory
SRC_DIR = os.path.dirname(os.path.abspath(__file__))  # Path to the src directory
CONFIG_FILENAME = os.path.join(SRC_DIR, 'cpf_config.json')  # Full path to the config file
FLAT_FILENAME = os.path.join(SRC_DIR, 'test_config1.json')  # Full path to the flat config file
#DATABASE_NAME = os.path.join(SRC_DIR, 'cpf_simulation.db')  # Full path to the database file
USER_FILE = os.path.join(SRC_DIR, "users.json")

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
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
def check_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed.encode())

def migrate_secret_answers(users):
    changed = False
    for user, data in users.items():
        secret_answer = data.get("secret_answer", "")
        # If not already a bcrypt hash (bcrypt hashes start with $2b$ or $2a$)
        if not (isinstance(secret_answer, str) and secret_answer.startswith("$2")):
            # Hash the plain secret answer (assume it's stored in lowercase)
            data["secret_answer"] = hash_password(secret_answer.lower())
            changed = True
    if changed:
        save_users(users)

def main()-> None:
    st.set_page_config(page_title="CPF Simulation Setup", layout="wide")
    
    session_state : bool  =  login_page()
    if session_state:
       
        mainpage()
   
   
    st.stop()
        
def mainpage()-> None:  
    
                                                 
    webbrowser.open_new_tab("CPF Simulation Configurator")
    st.title("🧾 CPF Simulation Configurator")
    st.subheader("🔧 Edit Parameters")
    updated_config = {}
    config = CPFConfig(CONFIG_FILENAME)
    for key, value in config.data.items():
        if isinstance(value, (int, float)):
            updated_value = st.number_input(key, value=value)
        elif isinstance(value, str):
            updated_value = st.text_input(key, value=value)
        else:
            updated_value = st.text_area(key, value=json.dumps(value))
        updated_config[key] = updated_value
    # what if the user pressed the web close browser button
    #if st.button("Close Browser"):                        
    #    return 
    # Save the updated configuration
    col1, col2, col3, col4, col5, col6  = st.columns(6)
    with col1:
        if st.button("💾 Save"):
            # Save the updated configuration to a file
            with open(CONFIG_FILENAME, "w") as f:
                json.dump(config.data, f, indent=4)
            st.success("Configuration saved successfully!")
    # Use the full path to the Python executable
    python_executable = sys.executable  # This gets the current Python executable being used
    with col2:
        if st.button("Run Simulation"):
            # Run the simulation script
            try:
                result = subprocess.run(
                    [python_executable, os.path.join(PATH, "cpf_run_simulation_v9.py")],
                    check=True,
                    capture_output=True,
                    text=True
                )
                # Save the simulation output to a temporary file
                simulation_output_path = os.path.join(SRC_DIR, "simulation_output.html")
                with open(simulation_output_path, "w") as f:
                    f.write(f"<pre>{result.stdout}</pre>")
                # Open the simulation output in a new browser tab
                #session_state = False
                webbrowser.open_new_tab(f"file://{simulation_output_path}")
                # Generate a link to open the simulation output in a new tab
                simulation_url = f"file://{simulation_output_path}"
                st.success("Simulation completed! Click the link below to view the output:")
                st.markdown(f'<a href="{simulation_url}" target="_blank">Open Simulation Output</a>', unsafe_allow_html=True)
            except subprocess.CalledProcessError as e:
                st.error("Simulation failed:")
                st.code(e.stderr or str(e))
    with col3:
        if st.button("🚀 Run CSV Report"):
            # Run the report generation script
            try:
                result = subprocess.run(
                    [python_executable, os.path.join(PATH, "cpf_build_reports_v1.py")],
                    check=True,
                    capture_output=True,
                    text=True
                )
                st.success("CSV Report generated successfully!")
                st.code(result.stdout)
            except subprocess.CalledProcessError as e:
                st.error("CSV Report generation failed:")
                st.code(e.stderr or str(e))
    with col4:
        if st.button("📊 Run Analysis"):
            # Run the analysis script
            try:
                result = subprocess.run(
                    [python_executable, os.path.join(PATH, "cpf_analysis_v1.py")],
                    check=True,
                    capture_output=True,
                    text=True
                )
                st.success("Analysis completed successfully!")
                st.code(result.stdout)
            except subprocess.CalledProcessError as e:
                st.error("Analysis failed:")
                st.code(e.stderr or str(e))
    with col5:
        import dicttoxml
        import pandas as pd
        # Read the contents of cpf_report.csv
        report_file_path = os.path.join(SRC_DIR, "cpf_report.csv")
        try:
            report_df = pd.read_csv(report_file_path)
            # Convert the DataFrame to a dictionary
            report_dict = report_df.to_dict(orient="records")
            # Convert the dictionary to XML
            xml_data = dicttoxml.dicttoxml(report_dict, custom_root="CPFReport", attr_type=False)
            # Provide the XML data for download
            st.download_button(
                label="Download XML",
                data=xml_data,
                file_name="cpf_report.xml",
                mime="application/xml",
            )
        except FileNotFoundError:
            st.error(f"File not found: {report_file_path}")
        except Exception as e:
            st.error(f"An error occurred while generating the XML: {e}")
    with col6:
        if st.button(" EXIT "):
            # Forcefully exit the Streamlit app
            #clear the page
           # Clear session state
            #login_page()
            st.rerun()
                           
def login_page()-> bool :
     # Clear session state
    users = load_users()
    migrate_secret_answers(users)
    
    # Initialize session state variables
    if "logged_in" not in st.session_state:
        st.session_state["logged_in"] = False
    if "register_mode" not in st.session_state:
        st.session_state["register_mode"] = False

    # Registration form
    if st.session_state["register_mode"]:
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
        create_btn = st.button("Create Account")
        cancel_btn = st.button("Cancel")
        if create_btn:
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
                st.success("Account created! Please log in.")
                st.session_state["register_mode"] = False
                st.rerun()
        if cancel_btn:
            st.session_state["register_mode"] = False
            st.rerun()
        return

    # Login form
    st.header("🔒 Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    secret_question = st.selectbox(
        "Secret Question",
        options=["Name of your pet ?", "Favourite book ?", "Your First School ?"],
        key="secret_question"
    )
    secret_answer = st.text_input("Secret Answer", key="secret_answer")
    login_btn = st.button("Login")
    forgot_btn = st.button("Forgot Password?")
    register_btn = st.button("Register")
    quit_btn = st.button("Quit")
    if quit_btn:
        return False
        
        
    if login_btn:
        if (
            username in users and
            check_password(password, users[username]["password"]) and
            users[username]["secret_question"] == secret_question and
            check_password(secret_answer.lower(), users[username]["secret_answer"])
        ):
            st.session_state["logged_in"] = True
            st.session_state["username"] = username
            st.success("Login successful!")
            return True
        else:
            st.error("Invalid username or password.")

    if register_btn:
        st.session_state["register_mode"] = True
        st.rerun()

    if forgot_btn:
        if username in users:
            user_secret_question = users[username]["secret_question"]
            st.info(f"Secret Question: {user_secret_question}")
            secret_answer_input = st.text_input("Secret Answer", key="reset_secret_answer")
            if "secret_verified" not in st.session_state:
                st.session_state["secret_verified"] = False
            if st.button("Verify Secret Answer"):
                if check_password(secret_answer_input.lower(), users[username]["secret_answer"]):
                    st.session_state["secret_verified"] = True
                    st.success("Secret answer verified! Please enter your new password.")
                else:
                    st.session_state["secret_verified"] = False
                    st.error("Incorrect secret answer.")
            if st.session_state["secret_verified"]:
                new_password = st.text_input("Enter new password", type="password", key="reset_pass")
                if st.button("Reset Password"):
                    users[username]["password"] = hash_password(new_password)
                    save_users(users)
                    st.success("Password reset! Please log in.")
                    st.session_state["secret_verified"] = False
                    st.rerun()
        else:
            st.error("Username not found.")

if __name__ == "__main__":

    main()
