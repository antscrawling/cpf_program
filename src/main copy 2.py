import streamlit as st
import bcrypt
import json
import os
from cpf_config_loader_v11 import CPFConfig
from datetime import datetime, date
import sys
import subprocess
import webbrowser

st.set_page_config(page_title="CPF Simulation Setup", layout="wide")

PATH = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = PATH
CONFIG_FILENAME = os.path.join(SRC_DIR, 'cpf_config.json')
FLAT_FILENAME = os.path.join(SRC_DIR, 'test_config1.json')
USER_FILE = os.path.join(SRC_DIR, "users.json")
username : str  = ""

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
    st.session_state["reset_mode"] = True
    user_secret_question = users[username]["secret_question"]
    st.info(f"Secret Question: **{user_secret_question}**")
    secret_answer_input = st.text_input("Your Answer to Secret Question", key="reset_secret_answer")      
    col1, col2 , col3, col4 = st.columns(4)
    with col1:
        if (
            st.button("Submit", key="reset_submit") 
            and
            check_password(
                secret_answer_input.lower(), 
                users[username]["secret_answer"]
                )
        ):
            st.session_state["reset_verified"] = True         
            new_password = st.text_input("Enter new password", type="password", key="reset_pass")
           
            with col3:
                if st.button("Reset Password", key="reset_password"):
                    users[username]["password"] = hash_password(new_password)
                    save_users(users)
                    st.success("Password reset successful! Please log in with your new password.")
                    st.session_state["reset_mode"] = False
                    st.session_state["reset_verified"] = False
                    st.rerun()

            with col4:
                if  st.button("Quit", key="reset_quit"):
                    st.session_state["reset_mode"] = False
                    st.session_state["reset_verified"] = False
                    st.rerun()

    with col2:
        if st.button("Cancel", key="reset_cancel"):
            st.session_state["reset_mode"] = False
            st.session_state["reset_verified"] = False
            st.rerun()

def show_login(myusers):
    st.header("🔒 Login")
    USERNAME = st.text_input("Username",key="username_input")
    password = st.text_input("Password", type="password",key="password_input")
    secret_question = st.selectbox(
        "Secret Question",
        options=["Name of your pet ?", "Favourite book ?", "Your First School ?"],
        key="secret_question"
    )
    secret_answer = st.text_input("Secret Answer", key="secret_answer")
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
                st.success("Login successful!")
                st.rerun()
            else:
                st.error("Invalid username, password, or secret answer.")
        return USERNAME
    with col2:
        if st.button("Forgot", key="forgot_button"):
            st.session_state["reset_mode"] = True
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
            st.rerun()            

def show_main_page():
    st.title("🧾 CPF Simulation Configurator")
    st.subheader("🔧 Edit Parameters")
    config = CPFConfig(CONFIG_FILENAME)
    updated_config = {}
    for key, value in config.data.items():
        if isinstance(value, (int, float)):
            updated_value = st.number_input(key, value=value)
        elif isinstance(value, str):
            updated_value = st.text_input(key, value=value)
        else:
            updated_value = st.text_area(key, value=json.dumps(value))
        updated_config[key] = updated_value

    col1, col2, col3, col4, col5, col6 = st.columns(6)
    with col1:
        if st.button("💾 Save",key="save_configuration"):
            config.data = updated_config
            with open(CONFIG_FILENAME, "w") as f:
                json.dump(config.data, f, indent=4)
            st.success("Configuration saved successfully!")
    with col2:
        if st.button("Run Simulation",key="run_simulation"):
            try:
                python_executable = sys.executable
                result = subprocess.run(
                    [python_executable, os.path.join(PATH, "cpf_run_simulation_v9.py")],
                    check=True, capture_output=True, text=True
                )
                output_path = os.path.join(SRC_DIR, "simulation_output.html")
                with open(output_path, "w") as f:
                    f.write(f"<pre>{result.stdout}</pre>")
                webbrowser.open_new_tab(f"file://{output_path}")
                st.success("Simulation completed! The output will open in a new tab.")
            except subprocess.CalledProcessError as e:
                st.error("Simulation failed:")
                st.code(e.stderr or str(e))
    with col3:
        if st.button("🚀 Run CSV Report",key="run_csv"):
            try:
                python_executable = sys.executable
                result = subprocess.run(
                    [python_executable, os.path.join(PATH, "cpf_build_reports_v1.py")],
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
                    [python_executable, os.path.join(PATH, "cpf_analysis_v1.py")],
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
            st.rerun()

def main():
    users = load_users()
    migrate_secret_answers(users)

    # Initialize session state variables if not set
    for key, val in [
        ("logged_in", False),
        ("register_mode", False),
        ("reset_mode", False),
        ("reset_verified", False),
        ("Main Page", False)
    ]:
        if key not in st.session_state:
            st.session_state[key] = val

    # Main logic flow
    USERNAME : str = show_login(users)
    if st.session_state["logged_in"] and st.session_state["Main Page"]:
        show_main_page()
    elif st.session_state["register_mode"]:
        show_registration(users)
    elif st.session_state["reset_mode"]:
        show_forgot_password(users, USERNAME)
    else:
        USERNAME : str = show_login(users)

if __name__ == "__main__":
    main()