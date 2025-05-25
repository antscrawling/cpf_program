import streamlit as st
import bcrypt
import json
import os
from cpf_config_loader_v11 import CPFConfig
from datetime import datetime, date
import sys
import subprocess
import webbrowser

# Set page config first (title and layout)
st.set_page_config(page_title="CPF Simulation Setup", layout="wide")

PATH = os.path.dirname(os.path.abspath(__file__))  # Dynamically determine the src directory
SRC_DIR = PATH  # Path to the src directory (same as script directory)
CONFIG_FILENAME = os.path.join(SRC_DIR, 'cpf_config.json')  # Full path to the config file
FLAT_FILENAME = os.path.join(SRC_DIR, 'test_config1.json')  # Full path to the flat config file
# DATABASE_NAME = os.path.join(SRC_DIR, 'cpf_simulation.db')  # Full path to the database file
USER_FILE = os.path.join(SRC_DIR, "users.json")

def load_users():
    """Load user credentials from the JSON file, or initialize the file if it doesn't exist."""
    if not os.path.exists(USER_FILE):
        with open(USER_FILE, "w") as f:
            json.dump({}, f)
        st.warning("No users found. Please register a new user.")
        return {}
    with open(USER_FILE, "r") as f:
        return json.load(f)

def save_users(users):
    """Save the users dictionary back to the JSON file."""
    with open(USER_FILE, "w") as f:
        json.dump(users, f)

def hash_password(password: str) -> str:
    """Hash a plaintext password using bcrypt."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def check_password(password: str, hashed: str) -> bool:
    """Verify a plaintext password against the given bcrypt hash."""
    return bcrypt.checkpw(password.encode(), hashed.encode())

def migrate_secret_answers(users):
    """
    One-time migration: ensure all secret answers in `users` are stored as bcrypt hashes.
    If any secret_answer is in plain text, replace it with a hashed version.
    """
    changed = False
    for user, data in users.items():
        secret_answer = data.get("secret_answer", "")
        # If not already a bcrypt hash (bcrypt hashes start with "$2")
        if not (isinstance(secret_answer, str) and secret_answer.startswith("$2")):
            # Hash the plain secret answer (stored in lowercase for consistency)
            data["secret_answer"] = hash_password(secret_answer.lower())
            changed = True
    if changed:
        save_users(users)

def main():
    """Main function to control the app flow between login and main page."""
    # Run the login page. It returns True if the user is authenticated.
    logged_in = login_page()
    if logged_in:
        # If login was successful (or already logged in), show the main application page.
        main_page()
    st.stop()  # Stop here so we don't run any code below (prevents fall-through when not logged in)

def main_page():
    """Render the main application page (shown after successful login)."""
    # Title and subtitle for main page
    st.title("🧾 CPF Simulation Configurator")
    st.subheader("🔧 Edit Parameters")

    # Load current configuration and create input fields for each parameter
    config = CPFConfig(CONFIG_FILENAME)
    updated_config = {}
    for key, value in config.data.items():
        if isinstance(value, (int, float)):
            updated_value = st.number_input(key, value=value)
        elif isinstance(value, str):
            updated_value = st.text_input(key, value=value)
        else:
            # For complex structures (e.g. lists or dicts), show as JSON text
            updated_value = st.text_area(key, value=json.dumps(value))
        updated_config[key] = updated_value

    # Action buttons in a horizontal layout
    col1, col2, col3, col4, col5, col6 = st.columns(6)
    # Save button
    with col1:
        if st.button("💾 Save"):
            # Update the configuration data and save to file
            config.data = updated_config  # apply the changes to the config object
            with open(CONFIG_FILENAME, "w") as f:
                json.dump(config.data, f, indent=4)
            st.success("Configuration saved successfully!")
    # Run Simulation button
    with col2:
        if st.button("Run Simulation"):
            # Run an external Python script to perform the simulation
            try:
                python_executable = sys.executable  # current Python interpreter
                result = subprocess.run(
                    [python_executable, os.path.join(PATH, "cpf_run_simulation_v9.py")],
                    check=True, capture_output=True, text=True
                )
                # Save the simulation output to an HTML file
                output_path = os.path.join(SRC_DIR, "simulation_output.html")
                with open(output_path, "w") as f:
                    f.write(f"<pre>{result.stdout}</pre>")
                # Open the simulation output in a new browser tab
                webbrowser.open_new_tab(f"file://{output_path}")
                st.success("Simulation completed! The output will open in a new tab.")
            except subprocess.CalledProcessError as e:
                st.error("Simulation failed:")
                st.code(e.stderr or str(e))
    # Run CSV Report button
    with col3:
        if st.button("🚀 Run CSV Report"):
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
    # Run Analysis button
    with col4:
        if st.button("📊 Run Analysis"):
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
    # Download XML button (converts a CSV report to XML format if available)
    with col5:
        import pandas as pd
        import dicttoxml
        report_file_path = os.path.join(SRC_DIR, "cpf_report.csv")
        try:
            report_df = pd.read_csv(report_file_path)
            report_dict = report_df.to_dict(orient="records")
            xml_data = dicttoxml.dicttoxml(report_dict, custom_root="CPFReport", attr_type=False)
            st.download_button(
                label="Download XML",
                data=xml_data,
                file_name="cpf_report.xml",
                mime="application/xml"
            )
        except FileNotFoundError:
            st.error(f"File not found: {report_file_path}")
        except Exception as e:
            st.error(f"An error occurred while generating the XML: {e}")
    # Exit/Logout button
    with col6:
        if st.button("🛑 EXIT"):
            # Log out the user and return to the login screen
            st.session_state["logged_in"] = False
            st.session_state.pop("username", None)
            st.rerun()

def login_page() -> bool:
    """Display the login or registration forms. Returns True if the user is logged in/authenticated."""
    # Load users database and ensure secret answers are hashed
    users = load_users()
    migrate_secret_answers(users)

    # Initialize session state variables for login process if not already set
    if "logged_in" not in st.session_state:
        st.session_state["logged_in"] = False
    if "register_mode" not in st.session_state:
        st.session_state["register_mode"] = False

    # **New**: If already logged in (from a previous interaction), skip login form
    if st.session_state["logged_in"]:
        return True

    # Registration form section
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
            # Validate and create new user
            if username in users:
                st.error("Username already exists.")
            elif new_password1 != new_password2:
                st.error("Passwords do not match.")
            elif not new_password1 or not new_password2:
                st.error("Password fields cannot be empty.")
            elif not secret_answer:
                st.error("Secret answer cannot be empty.")
            else:
                # Save the new user's credentials (password and secret answer hashed)
                users[username] = {
                    "password": hash_password(new_password1),
                    "secret_question": secret_question,
                    "secret_answer": hash_password(secret_answer.lower())
                }
                save_users(users)
                st.success("Account created successfully! Please log in.")
                # Exit registration mode and refresh to login
                st.session_state["register_mode"] = False
                st.rerun()
        if cancel_btn:
            # Cancel registration and return to login mode
            st.session_state["register_mode"] = False
            st.rerun()
        return False  # End the login_page function here (in register mode)

    # Login form section
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
        # User chose to quit the app
        st.stop()  # Stop the app (no further interface). Alternatively, could just do nothing.
        return False

    if login_btn:
        # When login button is clicked, verify credentials
        if (
            username in users and 
            check_password(password, users[username]["password"]) and
            users[username]["secret_question"] == secret_question and 
            check_password(secret_answer.lower(), users[username]["secret_answer"])
        ):
            # Credentials are correct -> log the user in
            st.session_state["logged_in"] = True
            st.session_state["username"] = username
            st.success("Login successful!")
            # Refresh the app after successful login to show the main page
            st.rerun()
        else:
            st.error("Invalid username, password, or secret answer.")

    if register_btn:
        # Switch to registration mode
        st.session_state["register_mode"] = True
        st.rerun()  # can also use st.rerun()

    if forgot_btn:
        # Password reset flow
        if username in users:
            # Show the secret question associated with the username
            user_secret_question = users[username]["secret_question"]
            st.info(f"Secret Question: **{user_secret_question}**")
            secret_answer_input = st.text_input("Your Answer to Secret Question", key="reset_secret_answer")
            # Initialize a verification flag in session state
            if "secret_verified" not in st.session_state:
                st.session_state["secret_verified"] = False
            if st.button("Verify Secret Answer"):
                if check_password(secret_answer_input.lower(), users[username]["secret_answer"]):
                    st.session_state["secret_verified"] = True
                    st.success("Secret answer verified! Please enter your new password below.")
                else:
                    st.session_state["secret_verified"] = False
                    st.error("Incorrect secret answer.")
            # If secret is verified, allow password reset
            if st.session_state["secret_verified"]:
                new_password = st.text_input("Enter new password", type="password", key="reset_pass")
                if st.button("Reset Password"):
                    users[username]["password"] = hash_password(new_password)
                    save_users(users)
                    st.success("Password reset successful! Please log in with your new password.")
                    st.session_state["secret_verified"] = False
                    st.rerun()
        else:
            st.error("Username not found.")
    # If none of the buttons were pressed, simply stay on the login page (return False by default)
    return False

# Run the main function when the script is executed
if __name__ == "__main__":
    main()